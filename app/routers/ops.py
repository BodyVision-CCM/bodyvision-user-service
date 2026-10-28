import logging

from fastapi import APIRouter, Response
from sqlalchemy import text

from app.db import get_engine
from app.deps import KeysDep

router = APIRouter()
log = logging.getLogger(__name__)


@router.get("/healthz", tags=["ops"], operation_id="healthz", summary="Liveness probe")
def healthz() -> dict:
    """Le processus répond. Ne teste volontairement aucune dépendance (sinon Kubernetes le redémarrerait
    à cause d'une panne de base de données, ce qui n'arrangerait rien)."""
    return {"status": "ok"}


@router.get(
    "/readyz",
    tags=["ops"],
    operation_id="readyz",
    summary="Readiness probe",
    responses={503: {"description": "PostgreSQL injoignable : ne pas envoyer de trafic à cette instance."}},
)
def readyz(response: Response) -> dict:
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        log.exception("readiness check failed")
        response.status_code = 503
        return {"status": "unavailable", "database": "down"}
    return {"status": "ready", "database": "up"}


@router.get(
    "/.well-known/jwks.json",
    tags=["auth"],
    operation_id="getJwks",
    summary="Clé publique de signature (JWKS)",
    description=(
        "Les autres services (Ingestion, Analytique) valident les jetons d'accès **localement** avec cette clé "
        "publique, sans appeler le service Auth à chaque requête. Le `kid` du jeton désigne la clé à utiliser."
    ),
)
def jwks(response: Response, keys: KeysDep) -> dict:
    response.headers["Cache-Control"] = "public, max-age=300"
    return {"keys": [keys.jwk]}
