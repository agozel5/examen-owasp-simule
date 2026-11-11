# Examen blanc - Sécurité des applications web (OWASP Top 10:2025)

Simulation du format de l'examen ESIEA : **Partie 1 CTF** (exploitation + correction de code, ~45 min) puis **Partie 2 QCM** (~15 min).
Barème : **30 % QCM, 70 % CTF**. Autorisé : cours, Cyber Library, internet, IA.

> ⚠️ Ces applications sont **volontairement vulnérables**. Elles ne tournent que sur `127.0.0.1`.
> Gardez le dépôt GitHub en **privé** et ne les déployez jamais.

## 0. Mise en place (hors chrono)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Dépôt GitHub (privé)
git init -b main && git add . && git commit -m "Examen blanc : état initial"
gh repo create agozel5/examen-owasp-simule --private --source=. --push
# ou : git remote add origin git@github.com:agozel5/examen-owasp-simule.git && git push -u origin main
```

La CI (onglet *Actions*) affiche un job par lab. Au départ les jobs sont **rouges** : c'est normal, les failles existent.

## 1. Déroulé

| Étape | Commande / action |
|---|---|
| Démarrer (lance le chrono de 45 min) | `python exam.py start` |
| Exploiter, récupérer les flags | navigateur + Burp/ZAP/curl |
| Valider un flag | `python exam.py submit lab1 FLAG{...}` |
| Mini-rapport par lab | copier `reports/TEMPLATE.md` en `reports/labN.md` |
| Patch | branche `patch/labN`, modifier `labs/.../app.py`, `pytest tests/test_labN.py` |
| Soumission du patch | `git push` puis **Pull Request** vers `main` (modèle fourni) |
| Fin | `python exam.py grade` puis `python exam.py stop` |

Vous n'avez pas besoin de tout finir : **priorisez** (flag + patch rapide d'abord, rapport en parallèle).
`python exam.py status` donne le temps restant.

### Règles
- **Boîte noire pendant l'exploitation** : ne lisez pas `labs/*/app.py` ni `tests/` avant d'avoir le flag du lab.
- Pour le patch, vous avez le droit (et le devoir) de lire le code.
- Ne modifiez pas `tests/`, `exam.py` ni les flags.
- Un patch qui casse le fonctionnement normal vaut 0.

## 2. Énoncés

| Lab | URL | Énoncé |
|---|---|---|
| **lab1 - FactuPro** | http://127.0.0.1:5001 | Compte fourni : `wiener` / `peter`. Un flag est caché dans les données d'un autre client. |
| **lab2 - ShopImages** | http://127.0.0.1:5002 | Le flag est dans `secret/flag.txt`, situé à côté du dossier `images/` servi par l'application. |
| **lab3 - Intranet RH** | http://127.0.0.1:5003 | Le flag est affiché dans `/admin`. Vous n'avez aucun identifiant administrateur. |
| **lab4 - StockCheck** | http://127.0.0.1:5004 | Le flag est sur `/admin` (console interne : 403 en accès direct). Passez par l'application. |
| **lab5 - AdminPanel** | http://127.0.0.1:5005 | Compte fourni : `wiener` / `peter`. Le flag est sur `/admin`, réservé à `administrator`. |

### Contraintes pour le patch
- **lab1** : un utilisateur ne doit lire que ses propres factures ; le propriétaire garde son accès.
- **lab2** : les images produits restent servies ; répondre 400/403/404 sinon.
- **lab3** : les connexions légitimes continuent de marcher, y compris pour un identifiant contenant une apostrophe.
- **lab4** : l'API doit continuer d'accepter `stockApi` pour joindre `<même hôte>/internal/stock?productId=N`, et rien d'autre.
- **lab5** : la connexion et `/admin` pour le vrai administrateur restent fonctionnels.

## 3. Barème

Par lab (100 pts) : **flag 40** + **patch 40** (tests sécurité *et* fonctionnels verts) + **mini-rapport 20** (corrigé à part).

```
note CTF /20   = moyenne des labs ramenée sur 20
note finale    = 0,7 x CTF + 0,3 x QCM
```

## 4. Après l'examen
Dites « **j'ai fini** » à Claude : correction de vos rapports, puis QCM chronométré de 15 min.
