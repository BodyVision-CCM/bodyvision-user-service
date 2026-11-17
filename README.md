# Auth – service Utilisateurs de BodyVision

Comptes, authentification JWT, profil et morphologie. **FastAPI + PostgreSQL**, dépôt indépendant :
il se teste, se construit et se déploie seul. Pour le lancer **avec les autres services**, voir le dépôt
https://github.com/BodyVision-CCM/bodyvision-infra-compose (cloné à côté de celui-ci ; `make db` y suffit pour avoir PostgreSQL seul).

Implémente les routes `auth`, `users`, `internal`, ainsi que les sondes et le JWKS (hors `/v1`), du contrat OpenAPI v0.4.2 (les sondes et le JWKS en font partie depuis la v0.4.1).

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
  Exception : une **fenêtre de tolérance au rejeu** (`REFRESH_REUSE_INTERVAL_SECONDS`, 30 s par défaut, 0 pour la
  désactiver) accepte un jeton tout juste échangé par rotation (réponse perdue, deux appels simultanés) : une nouvelle
  paire est émise, celle du premier appel est révoquée, les autres sessions ne sont pas touchées. Ce n'est toléré
  que si le **successeur direct du jeton n'a jamais servi** : s'il a déjà été échangé, quelqu'un d'autre détient la
  suite et le rejeu est traité comme un vol (purge). Un jeton révoqué par purge n'est jamais toléré.
- Clé de signature en fichier `0600` ; conteneur non-root.
- Erreurs au format du contrat `{ code, message, traceId }` ; `traceId` aussi dans `X-Request-ID` et les logs JSON.
- Le rôle SQL du service n'a accès qu'au schéma `utilisateurs`.

## Tests

```bash
make test    # 70 tests dans Docker, avec un PostgreSQL jetable (aucun port publié, données en mémoire)
```

Aucune dépendance au dépôt https://github.com/BodyVision-CCM/bodyvision-infra-compose : la même commande sert en CI. Les tests tournent contre un **vrai
PostgreSQL** (pas de mock de base) et incluent la **conformité au contrat** : routes, `operationId`, codes de
statut, paramètres, corps de requête et de réponse (types, bornes, champs requis, valeurs nulles) sont comparés
**dans les deux sens** à `contracts/openapi.yaml` : tout écart, d'un côté comme de l'autre, fait échouer le test.

Contre un PostgreSQL déjà initialisé (rôle `bv_utilisateurs` et schéma `utilisateurs` existants) :

```bash
pip install -r requirements-dev.txt
export DB_HOST=localhost DB_PORT=5432 DB_NAME=bodyvision DB_USER=bv_utilisateurs DB_PASSWORD=...
pytest
```

### Le contrat

`contracts/openapi.yaml` est un **instantané** du contrat (source : [dépôt `bodyvision-contracts`](https://github.com/BodyVision-CCM/bodyvision-contracts)), embarqué pour que
les tests tournent seuls. **À resynchroniser quand le contrat change.** Tester contre la source :
`CONTRACT_PATH=../bodyvision-contracts/openapi.yaml pytest`.

## Base de données et migrations

Le schéma `utilisateurs` et son rôle sont créés **avant** le service, par l'administrateur de la base (dans le projet
local : https://github.com/BodyVision-CCM/bodyvision-infra-compose/tree/master/postgres/init ; la liste des rôles et schémas
attendus par service y est dans le README) : le service n'a pas le droit de créer un schéma. Les **tables** sont créées
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

## Scan de sécurité

Deux contrôles, à relancer à chaque changement de dépendances (installer `pip-audit` et `bandit`, hors `requirements.txt`) :

```bash
pip-audit -r requirements.txt   # vulnérabilités connues des dépendances
bandit -r app                   # analyse statique du code du service
```

Dernier passage (17 nov. 2026) : `pip-audit` ne signale aucune vulnérabilité connue, `bandit` aucun problème
(0 faible, 0 moyen, 0 élevé).

## Limites connues

- **Deux refresh simultanés avec le même jeton** : le premier obtient T2, le second T3 et révoque T2. Si le client garde
  T2, il est déconnecté au refresh suivant (au bout d'environ 15 min, hors fenêtre). C'est la conséquence de « révoquer la
  paire du premier appel » ; la parade (un seul refresh à la fois) est côté mobile.
- **Pas de limitation du nombre de tentatives** sur `login` et `register` (force brute).
- **Pas de déconnexion**, de réinitialisation de mot de passe ni de vérification d'e-mail (absents du contrat v0.4.2).
- **Une seule clé de signature** dans le JWKS : pas de rotation sans interruption.
- `INTERNAL_SERVICE_TOKEN` est un secret partagé simple ; à durcir (mTLS, politique réseau).
- Un jeton d'accès reste valide jusqu'à son expiration (≤ 15 min), même après révocation des sessions.