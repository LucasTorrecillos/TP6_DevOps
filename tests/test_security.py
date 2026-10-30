"""Tests de conformité : rouges sur l'application d'origine, verts quand tout est corrigé."""
import base64
import os
import pickle
import re
import sqlite3

import app as shop

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
APP_SRC = os.path.join(ROOT, "app", "app.py")


def login(client, user="alice", pwd="alice123"):
    return client.post("/login", json={"username": user, "password": pwd})


# ---------- non-régression fonctionnelle ----------
def test_functional_login_and_search(client):
    assert login(client).status_code == 200
    r = client.get("/search", params={"q": "app"})
    assert [p["name"] for p in r.json()] == ["apple"]


def test_functional_own_invoice(client):
    login(client)
    assert client.get("/invoices/1").status_code == 200


# ---------- injections ----------
def test_sqli_login(client):
    r = client.post("/login", json={"username": "alice' --", "password": "x"})
    assert r.status_code == 401


def test_sqli_search(client):
    r = client.get("/search", params={"q": "' OR '1'='1"})
    assert r.json() == []


def test_command_injection(client):
    r = client.get("/ping", params={"host": "127.0.0.1;echo PWNED"})
    assert r.status_code in (400, 422)
    assert "PWNED" not in r.text


def test_eval_rejected(client):
    r = client.post("/calc", json={"expr": "__import__('os').getcwd()"})
    assert r.status_code in (400, 422)


def test_yaml_rce(client, tmp_path):
    marker = tmp_path / "yaml_pwned"
    payload = f"!!python/object/apply:os.system ['touch {marker}']"
    client.post("/import-yaml", content=payload)
    assert not marker.exists()


class _Evil:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


def test_pickle_rce(client, tmp_path):
    marker = tmp_path / "pickle_pwned"
    blob = base64.b64encode(pickle.dumps(_Evil(f"touch {marker}")))
    client.post("/import-profile", content=blob)
    assert not marker.exists()


# ---------- fichiers, XSS, SSRF ----------
def test_path_traversal(client):
    r = client.get("/files/..%2fapp.py")
    assert r.status_code in (400, 403, 404)
    assert "FastAPI(" not in r.text


def test_xss_escaped(client):
    r = client.get("/hello", params={"name": "<script>alert(1)</script>"})
    assert "<script>" not in r.text


def test_ssrf_blocked(client):
    r = client.get("/fetch", params={"url": "http://localhost:1/"})
    assert r.status_code in (400, 422)


# ---------- authentification, crypto, secrets ----------
def test_passwords_not_md5():
    shop.init_db()
    pwd = sqlite3.connect(os.environ["DB_PATH"]).execute(
        "SELECT password FROM users WHERE username='alice'").fetchone()[0]
    assert not re.fullmatch(r"[0-9a-f]{32}", pwd)


def test_no_hardcoded_secret_key():
    assert shop.SECRET_KEY != "super-secret-key-123"


def test_no_hardcoded_aws_key():
    assert "AKIA" not in open(APP_SRC, encoding="utf-8").read()


def test_session_cookie_flags(client):
    cookie = login(client).headers.get("set-cookie", "").lower()
    assert "httponly" in cookie
    assert "secure" in cookie
    assert "samesite" in cookie


def test_no_password_in_logs(client, caplog):
    login(client, "alice", "alice123")
    assert "alice123" not in caplog.text


# ---------- accès, headers, erreurs, config ----------
def test_idor(client):
    login(client)  # alice
    assert client.get("/invoices/2").status_code in (403, 404)  # facture de bob


def test_security_headers(client):
    h = client.get("/health").headers
    assert "content-security-policy" in h
    assert h.get("x-content-type-options") == "nosniff"


def test_no_stacktrace(client):
    r = client.get("/boom")
    assert r.status_code == 500
    assert "Traceback" not in r.text


def test_debug_off():
    assert shop.app.debug is False
    src = open(APP_SRC, encoding="utf-8").read()
    assert "debug=True" not in src
    assert "reload=True" not in src


# ---------- RBAC ----------
def test_functional_admin_can_manage_users(client):
    login(client, "admin", "admin123")
    assert client.get("/admin/users").status_code == 200
    assert client.delete("/users/3").status_code == 200


def test_rbac_user_cannot_list_users(client):
    login(client)  # alice, simple utilisateur
    assert client.get("/admin/users").status_code == 403


def test_rbac_user_cannot_delete_user(client):
    login(client)  # alice
    assert client.delete("/users/3").status_code == 403
    login(client, "admin", "admin123")
    assert client.get("/admin/users").status_code == 200  # bob existe toujours


def test_rbac_anonymous_rejected(client):
    assert client.delete("/users/3").status_code in (401, 403)


# ---------- dépendances, Docker, CI ----------
def test_dockerfile_hardened():
    d = open(os.path.join(ROOT, "app", "Dockerfile"), encoding="utf-8").read()
    assert "python:latest" not in d
    assert re.search(r"^USER\s+(?!root)\S+", d, re.M)


def test_requirements_pinned_with_hashes():
    r = open(os.path.join(ROOT, "app", "requirements.txt"), encoding="utf-8").read()
    assert "--hash=sha256:" in r


def test_ci_workflow_present():
    p = os.path.join(ROOT, ".github", "workflows", "security.yml")
    assert os.path.exists(p), "créez .github/workflows/security.yml"
    txt = open(p, encoding="utf-8").read().lower()
    for tool in ("bandit", "pip-audit", "gitleaks", "trivy"):
        assert tool in txt, f"{tool} manquant dans le workflow"
    assert "schedule" in txt, "ajoutez un scan planifié (cron)"
