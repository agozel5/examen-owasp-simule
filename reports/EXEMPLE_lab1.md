# Rapport de test d'intrusion — FactuPro (lab1)

> Exemple de rapport rempli, fourni à titre d'illustration du niveau de détail attendu.
> Les données (flag, PR) sont celles de l'examen blanc.

---

## 1. Synthèse

| | |
|---|---|
| **Application testée** | FactuPro — portail de facturation |
| **Référence** | VULN-01 |
| **Catégorie OWASP Top 10:2025** | A01 — Broken Access Control |
| **CWE** | CWE-639 — Authorization Bypass Through User-Controlled Key (IDOR) |
| **Sévérité** | Élevée |
| **Score CVSS v3.1** | 6.5 (`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`) |
| **Statut** | Corrigé (PR #1) |

**En une phrase (pour un non-technicien) :** Un client authentifié pouvait consulter les factures — et les notes internes qu'elles contiennent — de n'importe quel autre client de la plateforme, simplement en modifiant un numéro dans l'adresse.

---

## 2. Description technique

- **Composant / endpoint concerné** : `GET /api/invoices/<int:inv_id>` (`labs/lab1_idor/app.py`, fonction `get_invoice`)
- **Côté** : serveur
- **Niveau de la stack** : code
- **Cause racine** : le serveur vérifie que l'utilisateur est authentifié, mais ne vérifie jamais que l'identifiant de facture demandé (`inv_id`) appartient bien à l'utilisateur courant. L'identifiant est numérique et séquentiel, donc prévisible et énumérable.

---

## 3. Preuve de concept

**Pré-requis** : compte `wiener` / `peter` (factures légitimes : 1041, 1042)

**Requête** :
```http
GET /api/invoices/1045 HTTP/1.1
Host: 127.0.0.1:5001
Cookie: session=eyJ1aWQiOjF9...
```

**Réponse obtenue** :
```
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": 1045,
  "owner_id": 3,
  "label": "Audit externe",
  "amount": 4200.0,
  "memo": "Note interne : FLAG{...}"
}
```
Attendu : `403 Forbidden` (la facture appartient à `carlos`, `owner_id=3`, pas à `wiener`, `id=1`).

**Résultat** : flag récupéré dans le champ `memo`.

---

## 4. Impact métier

Un attaquant disposant d'un simple compte client peut énumérer l'ensemble des factures de la plateforme (`id` 1040 à 9999) et accéder aux données financières et notes internes de tous les clients : montants facturés, libellés, informations sensibles embarquées dans les mémos. Impact direct sur la **confidentialité** des données clients, avec un risque de non-conformité RGPD (accès non autorisé à des données à caractère personnel/commercial) et d'atteinte à l'image en cas de divulgation.

---

## 5. Recommandations

| Priorité | Action | Effort |
|---|---|---|
| Court terme | Vérifier `inv.owner_id == user.id` avant de renvoyer la ressource | Faible |
| Moyen terme | Filtrer la requête en base par `owner_id` plutôt que de charger puis vérifier en mémoire ; auditer tous les autres endpoints `/api/*` pour le même défaut | Moyen |
| Bonnes pratiques | Généraliser un contrôle d'autorisation centralisé (middleware) plutôt que de le répéter dans chaque route | — |

**Correctif appliqué** :
```diff
         inv = invoices.get(inv_id)
         if inv is None:
             return jsonify(error="facture introuvable"), 404
+        if inv["owner_id"] != user["id"]:
+            return jsonify(error="acces refuse"), 403
         return jsonify(inv)
```

**Principe de sécurité appliqué** : ne jamais faire confiance à un identifiant d'objet fourni par le client — vérifier systématiquement la propriété de la ressource côté serveur, indépendamment de l'authentification.

---

## 6. Validation

- [x] `python -m pytest tests/test_lab1.py` : 15/15 tests passent
- [x] Comportement fonctionnel normal préservé (un utilisateur continue d'accéder à ses propres factures)
- [x] Pull Request : #1 (fusionnée)

---

*Rapport rédigé dans le cadre de l'examen blanc — test d'intrusion web, ESIEA.*
