"""
Lab 5 - AdminPanel : session par JWT (OWASP A04/A07:2025)

Application d'EXAMEN volontairement vulnerable.
Ne jamais l'exposer sur un reseau : elle ne tourne que sur 127.0.0.1.
"""
import os
import secrets
import time
import warnings

import jwt
from flask import Flask, jsonify, render_template_string, request

warnings.filterwarnings("ignore", message="The HMAC key is")

INDEX = """<!doctype html><title>AdminPanel</title>
<h1>AdminPanel</h1>
<form method="post" action="/login">
  <input name="username" placeholder="Identifiant">
  <input name="password" type="password" placeholder="Mot de passe">
  <button>Connexion</button>
</form>
"""

ADMIN = """<!doctype html><title>Admin</title>
<h1>Panneau d'administration</h1>
<p>Secret de l'entreprise : {{ flag }}</p>
"""


def create_app():
    app = Flask(__name__)

    flag = os.environ.get("FLAG_LAB5", "FLAG{lab5-local-dev}")
    users = {
        "wiener": "peter",
        "carlos": secrets.token_urlsafe(12),
        "administrator": os.environ.get("LAB5_ADMIN_PASSWORD") or secrets.token_urlsafe(16),
    }

    jwt_secret = "password123"

    def make_token(sub):
        now = int(time.time())
        return jwt.encode({"sub": sub, "iat": now, "exp": now + 3600}, jwt_secret, algorithm="HS256")

    def read_token():
        token = request.cookies.get("session", "")
        try:
            return jwt.decode(token, jwt_secret, algorithms=["HS256"])
        except jwt.PyJWTError:
            return None

    @app.get("/")
    def index():
        return render_template_string(INDEX)

    @app.post("/login")
    def login():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            data = request.form
        username = data.get("username", "")
        if users.get(username) is None or users[username] != data.get("password", ""):
            return jsonify(error="identifiants invalides"), 401
        resp = jsonify(ok=True, user=username)
        resp.set_cookie("session", make_token(username), httponly=True)
        return resp

    @app.get("/api/me")
    def me():
        claims = read_token()
        if claims is None:
            return jsonify(error="authentification requise"), 401
        return jsonify(sub=claims["sub"])

    @app.get("/admin")
    def admin():
        claims = read_token()
        if claims is None:
            return "Authentification requise", 401
        if claims.get("sub") != "administrator":
            return "Acces refuse", 403
        return render_template_string(ADMIN, flag=flag)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5005)), debug=False)
