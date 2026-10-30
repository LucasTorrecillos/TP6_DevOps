# TP – Rendre « MiniShop » conforme

Cours 6 – Écrire du code Python sécurisé · durée indicative : 3 h · en binôme ou seul

## Contexte

`app/app.py` est une petite API **FastAPI** volontairement vulnérable. Elle expose des endpoints qui illustrent chacune des failles vues en cours. Votre mission : la rendre conforme, sans casser les fonctionnalités, et mettre en place la CI/CD qui le vérifie en continu.

## Mise en route

```bash
cd "TP06-Secure-Code"
python -m venv .venv && source .venv/bin/activate    # Windows : .venv\Scripts\activate
pip install -r app/requirements.txt pytest bandit pip-audit
cd app && python app.py                               # http://localhost:5000/docs
cd .. && pytest -q tests                              # la plupart des tests sont ROUGES
```

Les tests utilisent `/ping` (Linux/macOS/WSL recommandé). Initialisez un dépôt Git et **faites un commit par faille corrigée** (`git init`, message du type `fix(sqli): requêtes paramétrées`).

## Travail demandé

### Partie 1 – Injections (5 pts)
1. `/login` et `/search` : requêtes paramétrées.
2. `/ping` : plus de `shell=True`, validation de l'adresse IP (`ipaddress` ou type pydantic `IPvAnyAddress`), timeout.
3. `/calc` : supprimer `eval` (ex. `ast.literal_eval` ou parser arithmétique à liste blanche), répondre 400/422 si invalide.
4. `/import-yaml` : `yaml.safe_load`. `/import-profile` : remplacer pickle par du JSON validé par un modèle pydantic.

### Partie 2 – Fichiers, XSS, SSRF (3 pts)
5. `/files/{name}` : confiner au dossier `uploads/` (`resolve()` + `is_relative_to`).
6. `/hello` : utiliser `Jinja2Templates` (échappement automatique) ou `html.escape`.
7. `/fetch` : liste blanche d'hôtes, https uniquement, `timeout`, `verify=True`, pas de redirections.

### Partie 3 – Authentification, crypto, secrets (4 pts)
8. Mots de passe hachés avec argon2id (`argon2-cffi`) ou bcrypt, y compris pour les comptes de `init_db()`.
9. `SECRET_KEY` lue depuis la variable d'environnement du même nom (sans valeur par défaut), conservée en constante du module `app.py` ; supprimer la clé AWS en dur ; fournir un `.env.example` et un `.gitignore` qui exclut `.env`.
10. Jeton de session généré avec `secrets` (ou supprimé si inutile) ; cookie de session `Secure`, `HttpOnly`, `SameSite` (`SessionMiddleware(https_only=True, same_site="lax")`).
11. Ne plus logger les mots de passe.

### Partie 4 – Accès, en-têtes, erreurs, configuration (3 pts)
12. `/invoices/{id}` : vérifier que la facture appartient à l'utilisateur connecté (404 sinon), idéalement via une dépendance `Depends(current_user)`.
12b. **RBAC** : `GET /admin/users` et `DELETE /users/{id}` sont réservés au rôle admin (403 pour un simple utilisateur). Définir les rôles et leurs permissions dans un seul endroit (ex. dépendance `require("user:delete")`), refus par défaut.
13. En-têtes de sécurité : CSP, `X-Content-Type-Options: nosniff`, HSTS, `X-Frame-Options` (middleware HTTP `@app.middleware("http")`).
14. Gestionnaire d'erreurs générique : plus de stack trace ; détail uniquement dans les logs.
15. `FastAPI(debug=False)`, pas de `reload=True`, pas d'écoute sur `0.0.0.0` hors conteneur ; désactiver `/docs` et `/openapi.json` en production.
16. Bonus : limitation de débit sur `/login` (slowapi), modèles pydantic stricts pour toutes les entrées.

### Partie 5 – Dépendances et Dockerfile (2 pts)
17. Mettre à jour les dépendances vulnérables (`pip-audit` doit sortir propre) ; produire `requirements.in` + `requirements.txt` verrouillé avec hashes (`pip-compile --generate-hashes`).
18. Dockerfile : image de base épinglée (`python:3.12-slim`), utilisateur non-root (`USER`), `pip install --require-hashes --no-cache-dir`, `.dockerignore`, commande `uvicorn app:app --host 0.0.0.0 --port 5000` sans `--reload`.

### Partie 6 – CI/CD de sécurité (3 pts)
19. Créer `.github/workflows/security.yml` qui exécute au minimum **Bandit, pip-audit, gitleaks et Trivy**, bloque sur sévérité HIGH/CRITICAL, tourne sur push, pull request **et** en cron quotidien.
20. `permissions: contents: read`, actions épinglées par SHA de commit (les tags peuvent être réécrits : cf. l'incident Trivy/LiteLLM de mars 2026).
21. Activer Dependabot (`.github/dependabot.yml`, écosystèmes `pip` et `docker`).
22. Ajouter un job DAST (OWASP ZAP baseline sur `/openapi.json`) ou un job SBOM (CycloneDX) : au choix.

### Partie 7 – Scénario d'incident (rapport, `INCIDENT.md`)
Une version de `requests` utilisée par l'application est annoncée comme compromise. Décrivez, avec les commandes, votre réaction : détection, évaluation d'exposition, confinement, correction, rotation des secrets, retour d'expérience. Ce rapport est évalué à l'oral.

## Vérification

```bash
bash verify.sh        # Bandit, pip-audit, gitleaks, pytest
```

## Barème (20 points)

| Bloc | Points | Contrôle |
|---|---|---|
| Injections | 5 | tests `sqli`, `command`, `eval`, `yaml`, `pickle` |
| Fichiers, XSS, SSRF | 3 | tests `path_traversal`, `xss`, `ssrf` |
| Auth, crypto, secrets | 4 | tests mots de passe, secret key, AWS, cookies, logs ; gitleaks propre |
| Accès, RBAC, headers, erreurs, config | 3 | tests `idor`, `rbac`, headers, stacktrace, debug |
| Dépendances et Dockerfile | 2 | pip-audit propre, hashes, Dockerfile durci |
| CI/CD de sécurité | 3 | workflow présent et complet, Dependabot |

Les tests fonctionnels (`test_functional_*`) doivent rester verts : une correction qui casse l'application ne rapporte aucun point.

## Pistes et rappels

- Argon2 : `from argon2 import PasswordHasher`, `ph.hash(...)`, `ph.verify(hash, pwd)`.
- Le client de test utilise `https://testserver` pour que le cookie `Secure` soit renvoyé.
- Le test des cookies lit l'en-tête `Set-Cookie` de `/login` : il doit contenir `HttpOnly`, `Secure` et `SameSite`.
- Le test des hashes exige `--hash=sha256:` dans `app/requirements.txt`.
- Les codes 422 de validation pydantic sont acceptés pour les entrées invalides.
