"""Lab 1 - FactuPro (IDOR). Ne pas modifier ce fichier."""
import pytest
from lab1_idor.app import create_app

FLAG = "FLAG{TEST_LAB1_IDOR}"
CARLOS_PW = "carlos-test-password"

# Donnees de depart : wiener possede 1041 et 1042. Les autres factures
# (1043 a 1048) appartiennent a d'autres utilisateurs.
OWN = [1041, 1042]
OTHERS = list(range(1043, 1049))


@pytest.fixture
def make_client(monkeypatch):
    monkeypatch.setenv("FLAG_LAB1", FLAG)
    monkeypatch.setenv("LAB1_CARLOS_PASSWORD", CARLOS_PW)

    def _make(user="wiener", password="peter"):
        client = create_app().test_client()
        resp = client.post("/login", json={"username": user, "password": password})
        assert resp.status_code == 200, "le login doit continuer a fonctionner"
        return client

    return _make


# ---------------------------------------------------------------- securite
@pytest.mark.security
@pytest.mark.parametrize("inv_id", OTHERS + [1040, 1049, 9999])
def test_factures_des_autres_inaccessibles(make_client, inv_id):
    client = make_client()
    resp = client.get(f"/api/invoices/{inv_id}")
    assert resp.status_code in (403, 404), (
        f"wiener ne doit pas lire la facture {inv_id} (reponse {resp.status_code})"
    )
    assert FLAG not in resp.get_data(as_text=True)


@pytest.mark.security
def test_liste_ne_contient_que_mes_factures(make_client):
    client = make_client()
    ids = sorted(inv["id"] for inv in client.get("/api/invoices").get_json())
    assert ids == OWN


# ------------------------------------------------------------- fonctionnel
@pytest.mark.functional
@pytest.mark.parametrize("inv_id", OWN)
def test_mes_factures_restent_accessibles(make_client, inv_id):
    client = make_client()
    resp = client.get(f"/api/invoices/{inv_id}")
    assert resp.status_code == 200
    assert resp.get_json()["id"] == inv_id


@pytest.mark.functional
def test_proprietaire_voit_sa_facture(make_client):
    client = make_client("carlos", CARLOS_PW)
    resp = client.get("/api/invoices/1045")
    assert resp.status_code == 200
    assert FLAG in resp.get_data(as_text=True)


@pytest.mark.functional
def test_authentification_toujours_requise(monkeypatch):
    monkeypatch.setenv("FLAG_LAB1", FLAG)
    client = create_app().test_client()
    assert client.get("/api/invoices/1041").status_code == 401
    assert client.get("/api/invoices").status_code == 401


@pytest.mark.functional
def test_mauvais_mot_de_passe_refuse(monkeypatch):
    monkeypatch.setenv("FLAG_LAB1", FLAG)
    client = create_app().test_client()
    assert client.post("/login", json={"username": "wiener", "password": "x"}).status_code == 401
