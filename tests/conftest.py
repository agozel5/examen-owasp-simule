"""Outils communs aux tests de l'examen (ne pas modifier)."""
import threading
import urllib.error
import urllib.request

import pytest
from werkzeug.serving import make_server


@pytest.fixture
def live_server():
    """Demarre une application Flask sur 127.0.0.1 (port libre) et renvoie son URL."""
    servers = []

    def start(app):
        srv = make_server("127.0.0.1", 0, app, threaded=True)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        servers.append(srv)
        return f"http://127.0.0.1:{srv.server_port}"

    yield start
    for srv in servers:
        srv.shutdown()


@pytest.fixture
def http_get():
    """GET HTTP brut : renvoie (status, corps). Ne leve pas sur les 4xx/5xx."""

    def _get(url, headers=None):
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    return _get
