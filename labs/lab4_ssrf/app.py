"""
Lab 4 - StockCheck : verification de stock (OWASP A01:2025, Broken Access Control / SSRF)

Application d'EXAMEN volontairement vulnerable.
Ne jamais l'exposer sur un reseau : elle ne tourne que sur 127.0.0.1.

Architecture simulee : l'application appelle un "service de stock interne"
(/internal/stock) en joignant un jeton de service. Les routes /internal/* et
/admin ne repondent qu'aux appels portant ce jeton, c'est-a-dire aux appels
emis par le serveur lui-meme.
"""
import os
import secrets
import urllib.error
import urllib.request

from flask import Flask, Response, abort, render_template_string, request

INDEX = """<!doctype html><title>StockCheck</title>
<h1>StockCheck</h1>
<p>Casque audio - 59 EUR</p>
<form id="stock" method="post" action="/api/check-stock">
  <input type="hidden" name="stockApi" value="{{ stock_url }}">
  <button>Verifier le stock</button>
</form>
"""

ADMIN = """<!doctype html><title>Admin</title>
<h1>Console d'administration interne</h1>
<p>Secret de l'entreprise : {{ flag }}</p>
"""

STOCK = {"1": 42, "2": 7, "3": 0}


def create_app():
    app = Flask(__name__)

    flag = os.environ.get("FLAG_LAB4", "FLAG{lab4-local-dev}")
    internal_token = secrets.token_hex(16)

    @app.before_request
    def internal_only():
        # Zone "interne" : jeton de service obligatoire.
        if request.path.startswith("/internal") or request.path.startswith("/admin"):
            sent = request.headers.get("X-Internal-Token", "")
            if not secrets.compare_digest(sent, internal_token):
                abort(403)

    @app.get("/")
    def index():
        stock_url = request.host_url.rstrip("/") + "/internal/stock?productId=1"
        return render_template_string(INDEX, stock_url=stock_url)

    @app.route("/api/check-stock", methods=["GET", "POST"])
    def check_stock():
        url = request.values.get("stockApi", "")
        if not url:
            return "Parametre stockApi manquant", 400
        req = urllib.request.Request(url, headers={"X-Internal-Token": internal_token})
        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                body = resp.read(4096)
        except urllib.error.HTTPError as exc:
            return f"Erreur du service de stock ({exc.code})", exc.code
        except Exception:
            return "Service de stock injoignable", 500
        return Response(body, mimetype="text/plain")

    @app.get("/internal/stock")
    def internal_stock():
        pid = request.args.get("productId", "")
        return f"{STOCK.get(pid, 0)} unites en stock"

    @app.get("/admin")
    def admin():
        return render_template_string(ADMIN, flag=flag)

    return app


if __name__ == "__main__":
    create_app().run(
        host="127.0.0.1", port=int(os.environ.get("PORT", 5004)), debug=False, threaded=True
    )
