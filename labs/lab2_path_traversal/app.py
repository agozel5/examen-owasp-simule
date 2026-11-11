"""
Lab 2 - ShopImages : boutique en ligne (OWASP A01:2025, Broken Access Control)

Application d'EXAMEN volontairement vulnerable.
Ne jamais l'exposer sur un reseau : elle ne tourne que sur 127.0.0.1.

Arborescence geree par l'application (creee au demarrage) :
    <data_dir>/images/       -> les images publiques de la boutique
    <data_dir>/secret/flag.txt
"""
import base64
import mimetypes
import os
import tempfile

from flask import Flask, Response, render_template_string, request

# PNG 1x1 valide, sert d'image de produit.
PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)

PRODUCTS = {
    36: "Lampe de bureau",
    12: "Clavier mecanique",
    5: "Casque audio",
}

INDEX = """<!doctype html><title>ShopImages</title>
<h1>ShopImages</h1>
<ul>
{% for pid, name in products.items() %}
  <li><a href="/product/{{ pid }}">{{ name }}</a></li>
{% endfor %}
</ul>
"""

PRODUCT = """<!doctype html><title>{{ name }}</title>
<h1>{{ name }}</h1>
<img src="/image?filename={{ pid }}.png" width="120" alt="{{ name }}">
<p><a href="/">Retour</a></p>
"""


def create_app(data_dir=None):
    app = Flask(__name__)

    data_dir = data_dir or tempfile.mkdtemp(prefix="lab2-")
    images_dir = os.path.join(str(data_dir), "images")
    secret_dir = os.path.join(str(data_dir), "secret")
    os.makedirs(images_dir, exist_ok=True)
    os.makedirs(secret_dir, exist_ok=True)

    for pid in PRODUCTS:
        with open(os.path.join(images_dir, f"{pid}.png"), "wb") as fh:
            fh.write(PNG_1X1)
    with open(os.path.join(secret_dir, "flag.txt"), "w") as fh:
        fh.write(os.environ.get("FLAG_LAB2", "FLAG{lab2-local-dev}") + "\n")

    @app.get("/")
    def index():
        return render_template_string(INDEX, products=PRODUCTS)

    @app.get("/product/<int:pid>")
    def product(pid):
        if pid not in PRODUCTS:
            return "Produit introuvable", 404
        return render_template_string(PRODUCT, pid=pid, name=PRODUCTS[pid])

    @app.get("/image")
    def image():
        filename = request.args.get("filename", "")
        if "\x00" in filename:
            return "Requete invalide", 400
        base = os.path.realpath(images_dir)
        path = os.path.realpath(os.path.join(base, filename))
        if os.path.commonpath([base, path]) != base:
            return "Acces refuse", 403
        if not os.path.isfile(path):
            return "Image introuvable", 404
        with open(path, "rb") as fh:
            data = fh.read()
        mimetype = mimetypes.guess_type(path)[0] or "application/octet-stream"
        return Response(data, mimetype=mimetype)

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", 5002)), debug=False)
