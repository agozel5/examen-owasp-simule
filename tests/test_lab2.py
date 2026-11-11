"""Lab 2 - ShopImages (path traversal). Ne pas modifier ce fichier."""
import pytest
from lab2_path_traversal.app import create_app

FLAG = "FLAG{TEST_LAB2_TRAVERSAL}"

# Chaque payload est envoye tel quel dans la query string.
PAYLOADS = [
    "../secret/flag.txt",
    "....//secret/flag.txt",
    "..%2fsecret%2fflag.txt",
    "%2e%2e%2fsecret%2fflag.txt",
    "%252e%252e%252fsecret%252fflag.txt",
    "..%252fsecret%252fflag.txt",
    "....//....//....//....//etc/passwd",
    "../../../../../../etc/passwd",
    "/etc/passwd",
    "ABS_FLAG",  # chemin absolu du fichier flag, remplace dans le test
    "../secret/flag.txt%00.png",
    "..././secret/flag.txt",
]


@pytest.fixture
def setup(monkeypatch, tmp_path):
    monkeypatch.setenv("FLAG_LAB2", FLAG)
    app = create_app(data_dir=tmp_path)
    return app.test_client(), tmp_path


# ---------------------------------------------------------------- securite
@pytest.mark.security
@pytest.mark.parametrize("payload", PAYLOADS)
def test_traversee_de_chemin_bloquee(setup, payload):
    client, data_dir = setup
    if payload == "ABS_FLAG":
        payload = str(data_dir / "secret" / "flag.txt")
    resp = client.get(f"/image?filename={payload}")
    body = resp.get_data(as_text=True)
    assert FLAG not in body, "le flag ne doit pas etre lisible"
    assert "root:x:0:0" not in body, "/etc/passwd ne doit pas etre lisible"
    assert resp.status_code in (400, 403, 404), (
        f"repondre proprement par 400/403/404 (recu {resp.status_code})"
    )


# ------------------------------------------------------------- fonctionnel
@pytest.mark.functional
@pytest.mark.parametrize("pid", [36, 12, 5])
def test_images_produits_servies(setup, pid):
    client, _ = setup
    resp = client.get(f"/image?filename={pid}.png")
    assert resp.status_code == 200
    assert resp.data.startswith(b"\x89PNG")
    assert resp.mimetype == "image/png"


@pytest.mark.functional
def test_image_inconnue_404(setup):
    client, _ = setup
    assert client.get("/image?filename=inconnue.png").status_code == 404


@pytest.mark.functional
def test_pages_boutique(setup):
    client, _ = setup
    assert client.get("/").status_code == 200
    page = client.get("/product/36")
    assert page.status_code == 200
    assert "/image?filename=36.png" in page.get_data(as_text=True)
