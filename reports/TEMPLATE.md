# Rapport de test d'intrusion — [Nom du lab]

> Copier ce fichier en `reports/labN.md` et le remplir. Format inspiré des rapports de cabinets d'audit
> (synthèse managériale + fiche technique). Vise une page, deux maximum.

---

## 1. Synthèse

| | |
|---|---|
| **Application testée** | [Nom du lab] |
| **Référence** | VULN-0N |
| **Catégorie OWASP Top 10:2025** | A0X — [nom de la catégorie] |
| **CWE** | CWE-XXX — [nom] |
| **Sévérité** | Critique / Élevée / Moyenne / Faible |
| **Score CVSS v3.1** | X.X ([vecteur], ex. `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`) |
| **Statut** | Corrigé (PR #N) |

**En une phrase (pour un non-technicien) :** [ex. « Un utilisateur authentifié peut lire les factures de n'importe quel autre client en changeant un simple numéro dans l'URL. »]

---

## 2. Description technique

- **Composant / endpoint concerné** : `METHODE /chemin` (fichier : `labs/.../app.py:NN`)
- **Côté** : client / serveur
- **Niveau de la stack** : code / runtime / plateforme
- **Cause racine** : [quelle hypothèse du développeur est fausse — valeur contrôlée par le client crue sans vérification, requête construite par concaténation, etc.]

---

## 3. Preuve de concept (Proof of Concept)

**Pré-requis** : [ex. compte `wiener` / `peter`]

**Requête** :
```http
GET /chemin HTTP/1.1
Host: 127.0.0.1:500X
Cookie: session=...
```

**Réponse obtenue** :
```
HTTP/1.1 200 OK
...
```

**Résultat** : flag récupéré `FLAG{...}`

*(Captures d'écran Burp en pièce jointe si pertinent : `reports/screenshots/labN-*.png`)*

---

## 4. Impact métier

[Ce qu'un attaquant réel pourrait faire : fuite de données clients, usurpation de compte admin, atteinte à la confidentialité/intégrité/disponibilité, conformité (RGPD, PCI-DSS…) le cas échéant.]

---

## 5. Recommandations

| Priorité | Action | Effort |
|---|---|---|
| Court terme | [correctif appliqué ici] | Faible |
| Moyen terme | [mesure complémentaire, ex. durcissement, monitoring] | Moyen |
| Bonnes pratiques | [principe général à généraliser dans le code base] | — |

**Correctif appliqué** (diff) :
```diff
- [ligne vulnérable]
+ [ligne corrigée]
```

**Principe de sécurité appliqué** : [ex. « Ne jamais faire confiance à une valeur contrôlée par le client sans la revérifier côté serveur. »]

---

## 6. Validation

- [x] `python -m pytest tests/test_labN.py` : tous les tests passent
- [x] Comportement fonctionnel normal préservé
- [x] Pull Request : #N

---

*Rapport rédigé dans le cadre de l'examen blanc — test d'intrusion web, ESIEA.*
