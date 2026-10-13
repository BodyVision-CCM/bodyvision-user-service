# Auth – service Utilisateurs de BodyVision

Comptes, authentification JWT, profil et morphologie. **FastAPI + PostgreSQL**, dépôt indépendant :
il se teste, se construit et se déploie seul. Pour le lancer **avec les autres services**, voir le dépôt
`infra-compose` (cloné à côté de celui-ci).

Implémente les routes `auth`, `users` et `internal` du contrat OpenAPI v0.3.

| Route | Rôle |
|---|---|
| `POST /v1/auth/register` | Crée le compte et son profil vide, renvoie les jetons (201 ; 409 si l'e-mail existe) |
| `POST /v1/auth/login` | Connexion (même 401 si l'e-mail est inconnu ou le mot de passe faux) |
| `POST /v1/auth/refresh` | Échange un jeton de rafraîchissement contre une nouvelle paire (rotation) |
| `GET` / `PATCH /v1/users/me` | Profil : `heightCm`, `weightKg`, `level`, `displayName`, réglages |
| `GET /v1/internal/users/{userId}/morphology` | Appel service-à-service (Analytique), protégé par `INTERNAL_SERVICE_TOKEN` |
| `GET /.well-known/jwks.json` | Clé publique : les autres services valident les JWT sans appeler Auth |
| `GET /healthz`, `/readyz`, `/metrics` | Sondes (`/readyz` interroge PostgreSQL, 503 sinon) et métriques Prometheus |
| `/docs`, `/redoc`, `/openapi.json` | **Swagger UI**, ReDoc et contrat généré (désactivables : `ENABLE_DOCS=false`) |

**Essayer dans Swagger** : `POST /v1/auth/register` → copier le `accessToken` → bouton **Authorize** → le coller
→ essayer `GET /v1/users/me`.

## Sécurité

- Mots de passe : **argon2id**, minimum 10 caractères.
- Jeton d'accès : **JWT RS256**, 900 s. Jeton de rafraîchissement : **opaque, stocké haché, à usage unique**.
  Présenter un jeton déjà utilisé est traité comme un vol : **toutes les sessions du compte sont révoquées**.
- Clé de signature en fichier `0600` ; conteneur non-root.
- Erreurs au format du contrat `{ code, message, traceId }` ; `traceId` aussi dans `X-Request-ID` et les logs JSON.
- Le rôle SQL du service n'a accès qu'au schéma `utilisateurs`.

## Tests

```bash
make test    # 65 tests dans Docker, avec un PostgreSQL jetable (aucun port publié, données en mémoire)
```

Aucune dépendance au dépôt `infra-compose` : la même commande sert en CI. Les tests tournent contre un **vrai
PostgreSQL** (pas de mock de base) et incluent la **conformité au contrat** : routes, codes de statut, champs
et règle du mot de passe sont comparés à `contracts/openapi.yaml`.

Contre un PostgreSQL déjà initialisé (rôle `bv_utilisateurs` et schéma `utilisateurs` existants) :

```bash
pip install -r requirements-dev.txt
export DB_HOST=localhost DB_PORT=5432 DB_NAME=bodyvision DB_USER=bv_utilisateurs DB_PASSWORD=...
pytest
```

### Le contrat

`contracts/openapi.yaml` est un **instantané** du contrat (source : dépôt `bodyvision-contracts`), embarqué pour que
les tests tournent seuls. **À resynchroniser quand le contrat change.** Tester contre la source :
`CONTRACT_PATH=../bodyvision-contracts/openapi.yaml pytest`.

## Base de données et migrations

Le schéma `utilisateurs` et son rôle sont créés **avant** le service, par l'administrateur de la base (dans le projet
local : `infra-compose/postgres/init/`) : le service n'a pas le droit de créer un schéma. Les **tables** sont créées
par les migrations Alembic (`migrations/`), jouées au démarrage du conteneur si `RUN_MIGRATIONS=true`.
La migration 0001 est l'équivalent exact du DDL du ticket de modélisation. `alembic_version` vit dans le schéma
du service : chaque service a son propre historique.

## Image et configuration

```bash
make build   # image de production bodyvision/auth:dev (Dockerfile à la racine du dépôt)
```

Toute la configuration passe par variables d'environnement : voir **`.env.example`** (références, valeurs par défaut,
variables obligatoires). Le service refuse de démarrer sans `DB_PASSWORD` ni `INTERNAL_SERVICE_TOKEN`.

**Pour un déploiement** (à adapter à votre plateforme, aucun pipeline n'est fourni ici) :
`JWT_AUTOGENERATE_KEYS=false` et clé fournie par un secret (`JWT_PRIVATE_KEY_FILE` ou `JWT_PRIVATE_KEY`) ;
`ENABLE_DOCS=false` ; secrets (`DB_PASSWORD`, `INTERNAL_SERVICE_TOKEN`) hors du dépôt ;
`RUN_MIGRATIONS=false` dès qu'il y a plusieurs réplicas, avec un job qui lance `alembic upgrade head` ;
sondes sur `/healthz` (vivant) et `/readyz` (prêt).

## Limites connues

- **Pas de limitation du nombre de tentatives** sur `login` et `register` (force brute).
- **Pas de déconnexion**, de réinitialisation de mot de passe ni de vérification d'e-mail (absents du contrat v0.3).
- **Une seule clé de signature** dans le JWKS : pas de rotation sans interruption.
- `INTERNAL_SERVICE_TOKEN` est un secret partagé simple ; à durcir (mTLS, politique réseau).
- Un jeton d'accès reste valide jusqu'à son expiration (≤ 15 min), même après révocation des sessions.
- Les sondes `/healthz` et `/readyz` sont à la racine, alors que le contrat v0.3 les place sous `/v1` ; la route
  `/.well-known/jwks.json` n'est pas encore dans le contrat (à ajouter en v0.4).
