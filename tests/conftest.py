import os
import sys
import tempfile

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "app"))

_tmp = tempfile.mkdtemp()
os.environ["DB_PATH"] = os.path.join(_tmp, "test.db")
# Variable que l'application corrigée est censée lire (adaptez si besoin)
os.environ.setdefault("SECRET_KEY", "test-only-secret-not-for-prod")

import app as shop  # noqa: E402


@pytest.fixture()
def client():
    shop.init_db()
    # https:// pour que les cookies "Secure" soient renvoyés ; les 500 sont renvoyés au lieu d'être levés
    return TestClient(shop.app, base_url="https://testserver", raise_server_exceptions=False)
