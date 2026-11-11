"""Lab 5 - AdminPanel (JWT). Ne pas modifier ce fichier."""
import base64
import hashlib
import hmac
import json
import time

import pytest
from lab5_jwt.app import create_app

FLAG = "FLAG{TEST_LAB5_JWT}"
ADMIN_PW = "admin-jwt-test-password"

WEAK_SECRETS = [
    "password123", "secret", "secret1", "secret123", "changeme", "password",
    "admin", "123456", "supersecret", "jwt", "jwtsecret", "jwt_secret", "key",
    "your-256-bit-secret", "letmein", "qwerty", "s3cr3t", "test", "default",
    "flask", "dev", "development", "mysecret", "mysecretkey", "secretkey",
    "administrator", "wiener", "peter", "azerty", "motdepasse", "1234567890",
    "abc123", "password1", "root", "toor", "token", "HS256", "hmac", "",
]


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge(secret, sub="administrator", alg="HS256", exp_in=3600):
    """Fabrique un JWT a la main (sans PyJWT) signe avec `secret`."""
    header = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    now = int(time.time())
    payload = b64(json.dumps({"sub": sub, "iat": now, "exp": now + exp_in}).encode())
    signing_input = f"{header}.{payload}".encode()
    if alg == "none":
        return f"{header}.{payload}."
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{b64(sig)}"


@pytest.fixture
def make_client(monkeypatch):
    monkeypatch.setenv("FLAG_LAB5", FLAG)
    monkeypatch.setenv("LAB5_ADMIN_PASSWORD", ADMIN_PW)
    return lambda: create_app().test_client()


def login(client, user="wiener", password="peter"):
    return client.post("/login", json={"username": user, "password": password})


# ---------------------------------------------------------------- securite
@pytest.mark.security
@pytest.mark.parametrize("secret", WEAK_SECRETS)
def test_jwt_forge_avec_secret_faible_refuse(make_client, secret):
    client = make_client()
    client.set_cookie("session", forge(secret))
    resp = client.get("/admin")
    assert resp.status_code in (401, 403), f"token signe avec {secret!r} accepte"
    assert FLAG not in resp.get_data(as_text=True)


@pytest.mark.security
@pytest.mark.parametrize("alg", ["none", "None", "NONE"])
def test_jwt_alg_none_refuse(make_client, alg):
    client = make_client()
    header = b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    payload = b64(json.dumps({"sub": "administrator", "exp": int(time.time()) + 3600}).encode())
    client.set_cookie("session", f"{header}.{payload}.")
    resp = client.get("/admin")
    assert resp.status_code in (401, 403)
    assert FLAG not in resp.get_data(as_text=True)


@pytest.mark.security
def test_jwt_signature_alteree_refusee(make_client):
    client = make_client()
    login(client)
    token = client.get_cookie("session").value
    header, _, sig = token.split(".")
    evil = b64(json.dumps({"sub": "administrator", "exp": int(time.time()) + 3600}).encode())
    client.set_cookie("session", f"{header}.{evil}.{sig}")
    resp = client.get("/admin")
    assert resp.status_code in (401, 403)
    assert FLAG not in resp.get_data(as_text=True)


# ------------------------------------------------------------- fonctionnel
@pytest.mark.functional
def test_login_et_api_me(make_client):
    client = make_client()
    assert login(client).status_code == 200
    resp = client.get("/api/me")
    assert resp.status_code == 200
    assert resp.get_json()["sub"] == "wiener"


@pytest.mark.functional
def test_utilisateur_normal_pas_admin(make_client):
    client = make_client()
    login(client)
    assert client.get("/admin").status_code == 403


@pytest.mark.functional
def test_administrateur_legitime(make_client):
    client = make_client()
    assert login(client, "administrator", ADMIN_PW).status_code == 200
    resp = client.get("/admin")
    assert resp.status_code == 200
    assert FLAG in resp.get_data(as_text=True)


@pytest.mark.functional
def test_mauvais_mot_de_passe_et_sans_cookie(make_client):
    client = make_client()
    assert login(client, "wiener", "faux").status_code == 401
    assert client.get("/api/me").status_code == 401


@pytest.mark.functional
def test_token_aleatoire_refuse(make_client):
    client = make_client()
    client.set_cookie("session", "pas.un.jwt")
    assert client.get("/api/me").status_code == 401
