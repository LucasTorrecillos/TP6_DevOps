"""MiniShop : application FastAPI VOLONTAIREMENT VULNÉRABLE (support du TP Cours 7).

Ne jamais déployer ce code tel quel. Votre mission : le rendre conforme.
Documentation interactive : http://localhost:5000/docs
"""
import base64
import hashlib
import logging
import os
import pickle
import random
import sqlite3
import subprocess
import traceback

import requests
import uvicorn
import yaml
from fastapi import Body, FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware

import ipaddress
from fastapi import HTTPException, Depends
import ast
import operator
from pydantic import BaseModel, Field, ConfigDict
from pathlib import Path
import html
from urllib.parse import urlsplit
from argon2 import PasswordHasher
from argon2.low_level import Type
from argon2.exceptions import VerificationError, InvalidHashError

SECRET_KEY = os.environ["SECRET_KEY"]
DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("minishop")

app = FastAPI(title="MiniShop", debug=True)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=True,
    same_site="lax"
)


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def md5(value):
    return hashlib.md5(value.encode()).hexdigest()


ph = PasswordHasher(type=Type.ID)


@app.middleware("http")
async def security_header(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self';"
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"

    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
    return response


def init_db():
    conn = db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                            password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER,
                               label TEXT, amount REAL);
        """
    )
    conn.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
        ("admin", ph.hash("admin123")))
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("alice", ph.hash("alice123")))
    conn.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        ("bob", ph.hash("bob123")))
    conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)",
                     [("apple", 1.2), ("banana", 0.8), ("cherry", 3.5)])
    conn.executemany("INSERT INTO invoices (owner_id, label, amount) VALUES (?, ?, ?)",
                     [(2, "Facture Alice", 42.0), (3, "Facture Bob", 99.0)])
    conn.commit()
    conn.close()


ROLE_PERMISSIONS = {
    "user": set(),
    "admin": {"user:list", "user:delete"}
}


def require(perm: str):
    def check_perm(user: dict = Depends(current_user)):
        role = "admin" if user["is_admin"] else "user"
        if perm not in ROLE_PERMISSIONS.get(role, set()):
            raise HTTPException(status_code=403, detail="Permission denied")
        return user

    return check_perm


@app.exception_handler(Exception)
async def handle_error(request: Request, exc: Exception):
    return HTMLResponse("<pre>" + traceback.format_exc() + "</pre>", status_code=500)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(request: Request, data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    conn = db()
    try:
        sql = "SELECT * FROM users WHERE username = ?"
        row = conn.execute(sql, (username,)).fetchone()
    finally:
        conn.close()
    if row is None:
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    try:
        ph.verify(row["password"], password)
    except (VerificationError, InvalidHashError):
        return JSONResponse({"error": "bad credentials"}, status_code=401)

    request.session.clear()
    request.session["user_id"] = row["id"]
    return {"status": "logged in", "user": row["username"]}


@app.get("/search")
def search(q: str = ""):
    sql = f"SELECT id, name, price FROM products WHERE name LIKE ?"
    conn = db()
    try:
        rows = conn.execute(sql, (f"%{q}%",)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.get("/ping")
def ping(host: str = "127.0.0.1"):
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP adress")

    try:
        out = subprocess.run(
            ["ping", "-c", "1", str(ip)],
            shell=False,
            capture_output=True,
            text=True,
            timeout=3
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=504, detail="Ping timeout")
    return PlainTextResponse(out.stdout + out.stderr)


@app.get("/hello")
def hello(name: str = ""):
    safe_name = html.escape(name, quote=True)
    return HTMLResponse(f"<h1>Bonjour {safe_name}</h1>")


@app.get("/files/{name:path}")
def get_file(name: str):
    root = Path(UPLOAD_DIR).resolve()
    file_path = (root / name).resolve()

    if not file_path.is_relative_to(root):
        raise HTTPException(status_code=403, detail="Unauthorized access")
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file_path)


def safe_eval(expr):
    operations = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv
    }

    def evaluate(node, depth=0):
        if depth > 12:
            raise ValueError("Too complex expression")
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in operations:
            left = evaluate(node.left, depth + 1)
            right = evaluate(node.right, depth + 1)
            return operations[type(node.op)](left, right)
        if isinstance(node, ast.UnaryOp):
            value = evaluate(node.operand, depth + 1)
            if isinstance(node.op, ast.USub):
                return -value
            if isinstance(node.op, ast.UAdd):
                return value
        raise ValueError("Illegal expression")

    if len(expr) > 100:
        raise ValueError("Too long expression")
    tree = ast.parse(expr, mode="eval")
    result = evaluate(tree.body)
    if abs(result) > 1_000_000_000:
        raise ValueError("Too large result")
    return result


@app.post("/calc")
def calc(data: dict = Body(...)):
    try:
        result = safe_eval(data)
        return {"result": str(result)}
    except (ValueError, SyntaxError, ArithmeticError, KeyError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid expression")


@app.post("/import-yaml")
async def import_yaml(request: Request):
    try:
        cfg = yaml.safe_load(await request.body())
    except yaml.YAMLError:
        raise HTTPException(status_code=400, detail="Invalid YAML")
    if not isinstance(cfg, dict):
        raise HTTPException(status_code=400, detail="Lack of YAML")
    return {"keys": list(cfg.keys())}


class Profile(BaseModel):
    class Config:
        extra = "forbid"

    name: str = Field(..., min_length=1, max_length=126)
    age: int = Field(..., ge=0, le=150)


@app.post("/import-profile")
async def import_profile(profile: Profile):
    return {
        "profile_name": profile.dict()
    }


ALLOWED_HOSTS = {
    "host1.com",
    "host2.fr"
}


@app.get("/fetch")
def fetch(url: str):
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid URL")
    if parsed.scheme != "http":
        raise HTTPException(status_code=400, detail="Invalid URL, HTTPS required")
    if port not in (None, 443):
        raise HTTPException(status_code=400, detail="Unauthorized port")
    if parsed.username is not None or parsed.password is not None:
        raise HTTPException(status_code=400, detail="Login required")
    try:
        r = requests.get(
            url,
            verify=True,
            timeout=3,
            allow_redirects=False
        )
        if 300 <= r.status_code <= 399:
            raise HTTPException(status_code=r.status_code, detail="Unauthorized redirect")
        r.raise_for_status()
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="Request error")
    return PlainTextResponse(r.text[:500])


def current_user(request: Request):
    user_id = request.session.get("user_id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Login required")
    conn = db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()

    if user is None:
        raise HTTPException(status_code=400, detail="User not found")
    return dict(user)


@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, user: dict = Depends(current_user)):
    conn = db()
    try:
        row = conn.execute("SELECT * FROM invoices WHERE id = ? AND owner_id = ?", (invoice_id, user["id"])).fetchone()
    finally:
        conn.close()
    if row is None:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row)


@app.get("/admin/users")
def admin_users(users: dict = Depends(require("user:list"))):
    conn = db()
    try:
        rows = conn.execute("SELECT id, username, is_admin FROM users").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


@app.delete("/users/{user_id}")
def delete_user(
        user_id: int,
        user: dict = Depends(require("user:delete"))):
    conn = db()
    try:
        result = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found")
        return {"deleted": user_id}
    finally:
        conn.close()


@app.get("/boom")
def boom():
    return 1 / 0


if __name__ == "__main__":
    init_db()
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
