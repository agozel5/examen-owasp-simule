# Mini-rapport - labN (nom du lab)

> Copier ce fichier en `reports/labN.md` et le remplir. Une page maximum.

## 1. Vulnerabilite
- **Categorie OWASP Top 10:2025** :
- **Type** (ex. IDOR, SQLi...) :
- **Cote** : client / serveur
- **Niveau de la stack** : code / runtime / plateforme
- **Localisation** (endpoint, parametre, fichier:ligne) :

## 2. Cause
Pourquoi la faille existe (quelle valeur controlee par le client est crue sans verification ?).

## 3. Reproduction
1. Requete exacte (methode, URL, en-tetes, corps) :
2. Reponse obtenue (code HTTP, extrait) :
3. Flag recupere : `FLAG{...}`

## 4. Impact
Ce qu'un attaquant peut faire concretement.

## 5. Correctif
- Principe (regle appliquee) :
- Extrait du diff (avant / apres) :
- Lien de la Pull Request :

## 6. Verification
Tests passes (`pytest tests/test_labN.py`) et comportement normal conserve.
