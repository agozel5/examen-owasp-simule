"""
Lab 3 - Intranet RH : portail d'authentification (OWASP A05:2025, Injection)

Application d'EXAMEN volontairement vulnerable.
Ne jamais l'exposer sur un reseau : elle ne tourne que sur 127.0.0.1.
"""
import os
import secrets
import sqlite3

from flask import Flask, redirect, render_template_string, request, session

LOGIN = """<!doctype html><title>Intranet RH</title>
<h1>Intranet RH</h1>
{% if error %}<p style="color:#b00">{{ error }}</p>{% endif %}
<form method="post" action="/login">
  <input name="username" placeholder="Identifiant">
  <input name="password" type="password" placeholder="Mot de passe">
  <button>Connexion</button>
</form>
"""

ACCOUNT = """<!doctype html><title>Mon compte</title>
<h1>Connecte en tant que {{ username }}</h1>
<p>Role : {{ role }}</p>
<p><a href="/admin">Administration</a></p>
"""

ADMIN = """<!doctype html><title>Administration</title>
<h1>Panneau d'administration</h1>
<p>Secret de l'entreprise : {{ flag }}</p>
"""


def create_app():
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)

    flag = os.environ.get("FLAG_LAB3", "FLAG{lab3-local-dev}")
    admin_password = os.environ.get("LAB3_ADMIN_PASSWORD") or secrets.token_urlsafe(16)

    # Base SQLite en memoire, partagee entre les requetes.
    db_uri = f"file:lab3_{secrets.token_hex(4)}?mode=memory&cache=shared"
    keeper = sqlite3.connect(db_uri, uri=True, check_same_thread=False)
    keeper.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)"
    )
    keeper.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("administrator", admin_password, "admin"),
            ("wiener", "peter", "user"),
            ("carlos", secrets.token_urlsafe(12), "user"),
            ("d'artagnan", "mousquetaire", "user"),
        ],
    )
    keeper.commit()
    app.config["DB_KEEPER"] = keeper  # garde la base en memoire vivante

    @app.get("/")
    def index():
        return render_template_string(LOGIN, error=None)

    @app.post("/login")
    def login():
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = sqlite3.connect(db_uri, uri=True)
        try:
            query = (
                "SELECT id, username, role FROM users WHERE username = '"
                + username
                + "' AND password = '"
                + password
                + "'"
            )
            row = conn.execute(query).fetchone()
        except sqlite3.Error:
            return "Erreur interne", 500
        finally:
            conn.close()
        if row is None:
            return render_template_string(LOGIN, error="Identifiants invalides"), 401
        session["uid"], session["username"], session["role"] = row
        return redirect("/account")

    @app.get("/account")
    def account():
        if "uid" not in session:
            return "Authentification requise", 401
        return render_template_string(ACCOUNT, username=session["username"], role=session["role"])

    @app.get("/admin")
    def admin():
        if "uid" not in session:
            return "Authentification requise", 401
        if session.get("role") != "admin":
            return "Acces refuse", 403
        return render_template_string(ADMIN, flag=flag)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5003)), debug=False)
