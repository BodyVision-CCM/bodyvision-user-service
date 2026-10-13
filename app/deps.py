"""Dépendances FastAPI : utilisateur courant (JWT) et authentification service-à-service."""

import hmac
import uuid
from typing import Annotated

import jwt
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.db import get_db
from app.errors import unauthorized
from app.models import Utilisateur
from app.security import JwtKeys, get_keys

# auto_error=False : c'est notre gestionnaire qui répond, au format d'erreur du contrat.
# scheme_name = noms des schémas de sécurité du contrat (bearerAuth, serviceToken).
user_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="bearerAuth",
    bearerFormat="JWT",
    description="Jeton d'accès (`accessToken`) obtenu via `/v1/auth/login`, `/v1/auth/register` ou `/v1/auth/refresh`.",
)
service_bearer = HTTPBearer(
    auto_error=False,
    scheme_name="serviceToken",
    description="Jeton partagé entre services (variable `INTERNAL_SERVICE_TOKEN`). Réservé aux appels internes.",
)

SettingsDep = Annotated[Settings, Depends(get_settings)]
DbDep = Annotated[Session, Depends(get_db)]
KeysDep = Annotated[JwtKeys, Depends(get_keys)]


def get_current_user(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(user_bearer)],
    db: DbDep,
    keys: KeysDep,
    settings: SettingsDep,
) -> Utilisateur:
    if creds is None:
        raise unauthorized("UNAUTHENTICATED", "Authentification requise.")
    try:
        claims = keys.decode_access_token(creds.credentials, settings)
    except jwt.ExpiredSignatureError:
        raise unauthorized("TOKEN_EXPIRED", "Le jeton d'accès a expiré.") from None
    except jwt.InvalidTokenError:
        raise unauthorized("INVALID_TOKEN", "Jeton d'accès invalide.") from None
    try:
        user_id = uuid.UUID(claims["sub"])
    except ValueError:
        raise unauthorized("INVALID_TOKEN", "Jeton d'accès invalide.") from None
    user = db.get(Utilisateur, user_id)
    if user is None:  # compte supprimé alors que le jeton est encore valide
        raise unauthorized("INVALID_TOKEN", "Jeton d'accès invalide.")
    return user


def require_service_token(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(service_bearer)], settings: SettingsDep
) -> None:
    expected = settings.internal_service_token.get_secret_value().encode()
    # Comparaison à temps constant : ne révèle pas le jeton par mesure du temps de réponse.
    if creds is None or not hmac.compare_digest(creds.credentials.encode(), expected):
        raise unauthorized("INVALID_SERVICE_TOKEN", "Jeton de service absent ou invalide.")
