import logging

from fastapi import APIRouter, Response
from sqlalchemy import text

from app.db import get_engine
from app.deps import KeysDep
from app.schemas import Jwk, JwkSet, Liveness, Readiness

router = APIRouter()
log = logging.getLogger(__name__)


@router.get("/healthz", tags=["ops"], operation_id="liveness", summary="Liveness probe", response_model=Liveness)
def healthz() -> Liveness:
    """Le processus répond. Ne teste volontairement aucune dépendance (sinon Kubernetes le redémarrerait
    à cause d'une panne de base de données, ce qui n'arrangerait rien)."""
    return Liveness(status="ok")


@router.get(
    "/readyz",
    tags=["ops"],
    operation_id="readiness",
    summary="Readiness probe",
    response_model=Readiness,
    responses={
        503: {
            "model": Readiness,
            "description": "PostgreSQL injoignable : ne pas envoyer de trafic à cette instance.",
        }
    },
)
def readyz(response: Response) -> Readiness:
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        log.exception("readiness check failed")
        response.status_code = 503
        return Readiness(status="unavailable", database="down")
    return Readiness(status="ready", database="up")


@router.get(
    "/.well-known/jwks.json",
    tags=["auth"],
    operation_id="getJwks",
    summary="Clé publique de signature (JWKS)",
    response_model=JwkSet,
    responses={200: {"headers": {"Cache-Control": {"schema": {"type": "string"}, "description": "public, max-age=300"}}}},
    description=(
        "Les autres services (Ingestion, Analytique) valident les jetons d'accès **localement** avec cette clé "
        "publique, sans appeler le service Auth à chaque requête. Le `kid` du jeton désigne la clé à utiliser."
    ),
)
def jwks(response: Response, keys: KeysDep) -> JwkSet:
    response.headers["Cache-Control"] = "public, max-age=300"
    return JwkSet(keys=[Jwk(**keys.jwk)])
