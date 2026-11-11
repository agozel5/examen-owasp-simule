"""Lab 4 - StockCheck (SSRF). Ne pas modifier ce fichier.

Contrainte fonctionnelle : l'API doit continuer d'accepter le parametre
`stockApi` pour joindre le service de stock de l'application
(`<meme hote>/internal/stock?productId=N`).
"""
import urllib.parse

import pytest
from lab4_ssrf.app import create_app

FLAG = "FLAG{TEST_LAB4_SSRF}"


@pytest.fixture
def server(monkeypatch, live_server):
    monkeypatch.setenv("FLAG_LAB4", FLAG)
    base = live_server(create_app())
    return base, base.rsplit(":", 1)[1]  # (url de base, port)


def check(http_get, base, stock_api):
    quoted = urllib.parse.quote(stock_api, safe="")
    return http_get(f"{base}/api/check-stock?stockApi={quoted}")


def attack_urls(port):
    return [
        f"http://127.0.0.1:{port}/admin",
        f"http://localhost:{port}/admin",
        f"http://127.1:{port}/admin",
        f"http://2130706433:{port}/admin",
        f"http://0x7f000001:{port}/admin",
        f"http://0.0.0.0:{port}/admin",
        f"http://127.0.0.1:{port}/%61dmin",
        f"http://127.0.0.1:{port}/admin?x=/internal/stock",
        f"http://127.0.0.1:{port}/admin#/internal/stock",
        "file:///etc/passwd",
    ]


# ---------------------------------------------------------------- securite
@pytest.mark.security
@pytest.mark.parametrize("index", range(10))
def test_ssrf_bloquee(server, http_get, index):
    base, port = server
    url = attack_urls(port)[index]
    status, body = check(http_get, base, url)
    assert FLAG not in body, f"SSRF reussie avec stockApi={url}"
    assert "root:x:0:0" not in body, f"lecture locale reussie avec stockApi={url}"


# ------------------------------------------------------------- fonctionnel
@pytest.mark.functional
def test_service_de_stock_toujours_joignable(server, http_get):
    base, _ = server
    status, body = check(http_get, base, f"{base}/internal/stock?productId=1")
    assert status == 200
    assert "42" in body


@pytest.mark.functional
def test_autre_produit(server, http_get):
    base, _ = server
    status, body = check(http_get, base, f"{base}/internal/stock?productId=2")
    assert status == 200
    assert "7" in body


@pytest.mark.functional
def test_acces_direct_interdit_sans_jeton(server, http_get):
    base, _ = server
    assert http_get(f"{base}/admin")[0] == 403
    assert http_get(f"{base}/internal/stock?productId=1")[0] == 403


@pytest.mark.functional
def test_page_accueil(server, http_get):
    base, _ = server
    status, body = http_get(base + "/")
    assert status == 200
    assert "stockApi" in body
