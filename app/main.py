import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from prometheus_fastapi_instrumentator import Instrumentator

from app import __version__
from app.config import get_settings
from app.db import get_engine
from app.errors import register_exception_handlers
from app.logging_config import RequestContextMiddleware, setup_logging
from app.routers import auth, internal, ops, users
from app.security import get_keys

DESCRIPTION = """
Service **Utilisateurs / Authentification** de BodyVision : comptes, connexion, profil et morphologie.

**Tester les routes protégées** : appelez `POST /v1/auth/register` (ou `/login`), copiez le `accessToken`,
cliquez sur **Authorize** et collez-le.

**Jetons**
- *Accès* : JWT signé RS256, durée courte (`expiresIn`, 900 s par défaut).
- *Rafraîchissement* : jeton opaque à usage unique (rotation), valable 30 jours.
- La clé publique est publiée sur `/.well-known/jwks.json` pour les autres services.

**Erreurs** : toutes au format `{ "code", "message", "traceId" }` (schéma `Error` du contrat OpenAPI).
Le `traceId` est aussi renvoyé dans l'en-tête `X-Request-ID` ; fournissez-le pour retrouver une requête dans les logs.
"""

TAGS = [
    {"name": "auth", "description": "Inscription, connexion, renouvellement des jetons, clé publique."},
    {"name": "users", "description": "Profil de l'utilisateur connecté (morphologie, réglages)."},
    {"name": "internal", "description": "Appels service-à-service. **Non exposé par l'Ingress.**"},
    {"name": "ops", "description": "Sondes Kubernetes."},
]

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_keys()  # échoue tout de suite (au lieu de la 1re requête) si la clé de signature est introuvable
    log.info("auth service started", extra={"version": __version__})
    yield
    get_engine().dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    setup_logging(settings.log_level)

    app = FastAPI(
        title="BodyVision – Service Auth",
        version=__version__,
        summary="Comptes, authentification JWT et profil.",
        description=DESCRIPTION,
        openapi_tags=TAGS,
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url="/redoc" if settings.enable_docs else None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.add_middleware(RequestContextMiddleware)
    register_exception_handlers(app)

    for r in (auth.router, users.router, internal.router, ops.router):
        app.include_router(r)

    Instrumentator(excluded_handlers=["/metrics", "/healthz", "/readyz"]).instrument(app).expose(
        app, endpoint="/metrics", include_in_schema=False
    )
    return app


app = create_app()
