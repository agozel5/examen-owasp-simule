"""
Lab 1 - FactuPro : API de facturation (OWASP A01:2025, Broken Access Control)

Application d'EXAMEN volontairement vulnerable.
Ne jamais l'exposer sur un reseau : elle ne tourne que sur 127.0.0.1.
"""
import os
import secrets

from flask import Flask, jsonify, redirect, render_template_string, request, session

INDEX = """<!doctype html><title>FactuPro</title>
<h1>FactuPro</h1>
<p>Portail de facturation clients.</p>
<form method="post" action="/login">
  <input name="username" placeholder="Identifiant">
  <input name="password" type="password" placeholder="Mot de passe">
  <button>Connexion</button>
</form>
"""

ACCOUNT = """<!doctype html><title>FactuPro - Mon compte</title>
<h1>Bonjour {{ user }}</h1>
<h2>Mes factures</h2>
<ul>
{% for inv in invoices %}
  <li><a href="/api/invoices/{{ inv.id }}">Facture {{ inv.id }}</a> - {{ inv.label }} ({{ inv.amount }} EUR)</li>
{% endfor %}
</ul>
"""


def create_app():
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)

    flag = os.environ.get("FLAG_LAB1", "FLAG{lab1-local-dev}")

    users = {
        "wiener": {"id": 1, "password": "peter"},
        "alice": {"id": 2, "password": secrets.token_urlsafe(12)},
        "carlos": {
            "id": 3,
            "password": os.environ.get("LAB1_CARLOS_PASSWORD") or secrets.token_urlsafe(12),
        },
        "bob": {"id": 4, "password": secrets.token_urlsafe(12)},
    }

    invoices = {
        1041: {"id": 1041, "owner_id": 1, "label": "Abonnement mensuel", "amount": 49.0, "memo": ""},
        1042: {"id": 1042, "owner_id": 1, "label": "Formation securite", "amount": 120.0, "memo": ""},
        1043: {"id": 1043, "owner_id": 2, "label": "Licence logiciel", "amount": 310.0, "memo": ""},
        1044: {"id": 1044, "owner_id": 2, "label": "Support annuel", "amount": 890.0, "memo": ""},
        1045: {"id": 1045, "owner_id": 3, "label": "Audit externe", "amount": 4200.0,
               "memo": "Note interne : " + flag},
        1046: {"id": 1046, "owner_id": 3, "label": "Hebergement", "amount": 75.0, "memo": ""},
        1047: {"id": 1047, "owner_id": 4, "label": "Materiel reseau", "amount": 560.0, "memo": ""},
        1048: {"id": 1048, "owner_id": 4, "label": "Maintenance", "amount": 95.0, "memo": ""},
    }

    def current_user():
        uid = session.get("uid")
        for name, u in users.items():
            if u["id"] == uid:
                return {"id": uid, "username": name}
        return None

    @app.get("/")
    def index():
        return render_template_string(INDEX)

    @app.post("/login")
    def login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            data = request.form
        user = users.get(data.get("username", ""))
        if user is None or user["password"] != data.get("password", ""):
            return jsonify(error="identifiants invalides"), 401
        session["uid"] = user["id"]
        if request.is_json:
            return jsonify(ok=True)
        return redirect("/account")

    @app.get("/account")
    def account():
        user = current_user()
        if user is None:
            return redirect("/")
        mine = [i for i in invoices.values() if i["owner_id"] == user["id"]]
        return render_template_string(ACCOUNT, user=user["username"], invoices=mine)

    @app.get("/api/me")
    def me():
        user = current_user()
        if user is None:
            return jsonify(error="authentification requise"), 401
        return jsonify(user)

    @app.get("/api/invoices")
    def list_invoices():
        user = current_user()
        if user is None:
            return jsonify(error="authentification requise"), 401
        return jsonify([i for i in invoices.values() if i["owner_id"] == user["id"]])

    @app.get("/api/invoices/<int:inv_id>")
    def get_invoice(inv_id):
        user = current_user()
        if user is None:
            return jsonify(error="authentification requise"), 401
        inv = invoices.get(inv_id)
        if inv is None:
            return jsonify(error="facture introuvable"), 404
        return jsonify(inv)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5001)), debug=False)
