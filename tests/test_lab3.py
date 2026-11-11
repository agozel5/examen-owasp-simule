"""Lab 3 - Intranet RH (injection SQL). Ne pas modifier ce fichier."""
import pytest
from lab3_sqli.app import create_app

FLAG = "FLAG{TEST_LAB3_SQLI}"
ADMIN_PW = "admin-test-password"

PAYLOADS = [
    ("administrator'--", "x"),
    ("administrator' --", "x"),
    ("administrator'/*", "*/--"),
    ("' OR '1'='1' --", "x"),
    ("' OR 1=1--", "x"),
    ("x", "' OR '1'='1"),
    ("administrator", "' OR '1'='1"),
    ("' OR 1=1 LIMIT 1 --", "x"),
    ("' UNION SELECT 1,'administrator','admin'--", "x"),
    ("x' UNION SELECT 1,'administrator','admin' --", "x"),
]


@pytest.fixture
def make_client(monkeypatch):
    monkeypatch.setenv("FLAG_LAB3", FLAG)
    monkeypatch.setenv("LAB3_ADMIN_PASSWORD", ADMIN_PW)
    return lambda: create_app().test_client()


# ---------------------------------------------------------------- securite
@pytest.mark.security
@pytest.mark.parametrize("username,password", PAYLOADS)
def test_injection_sql_bloquee(make_client, username, password):
    client = make_client()
    client.post("/login", data={"username": username, "password": password})
    admin = client.get("/admin")
    assert admin.status_code in (401, 403), "aucune session ne doit etre obtenue"
    assert FLAG not in admin.get_data(as_text=True)
    account = client.get("/account")
    assert "Connecte en tant que" not in account.get_data(as_text=True)


# ------------------------------------------------------------- fonctionnel
@pytest.mark.functional
def test_connexion_utilisateur_normal(make_client):
    client = make_client()
    client.post("/login", data={"username": "wiener", "password": "peter"})
    account = client.get("/account")
    assert account.status_code == 200
    assert "wiener" in account.get_data(as_text=True)
    assert client.get("/admin").status_code == 403


@pytest.mark.functional
def test_connexion_administrateur(make_client):
    client = make_client()
    client.post("/login", data={"username": "administrator", "password": ADMIN_PW})
    admin = client.get("/admin")
    assert admin.status_code == 200
    assert FLAG in admin.get_data(as_text=True)


@pytest.mark.security
def test_identifiant_avec_apostrophe(make_client):
    """Un nom legitime contenant ' doit pouvoir se connecter (pas de blacklist).

    Rouge tant que la requete est construite par concatenation.
    """
    client = make_client()
    client.post("/login", data={"username": "d'artagnan", "password": "mousquetaire"})
    account = client.get("/account")
    assert account.status_code == 200
    assert "artagnan" in account.get_data(as_text=True)


@pytest.mark.functional
def test_mauvais_mot_de_passe_refuse(make_client):
    client = make_client()
    resp = client.post("/login", data={"username": "wiener", "password": "faux"})
    assert resp.status_code == 401
    assert client.get("/account").status_code == 401
