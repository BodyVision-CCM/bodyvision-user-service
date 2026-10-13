import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path

from app.deps import DbDep, require_service_token
from app.errors import AppError, Error
from app.models import Utilisateur
from app.schemas import Morphology, to_morphology

# Appels service-à-service uniquement : ce préfixe ne doit PAS être routé par l'Ingress public.
router = APIRouter(
    prefix="/v1/internal",
    tags=["internal"],
    dependencies=[Depends(require_service_token)],
    responses={401: {"model": Error, "description": "Jeton de service absent ou invalide."}},
)


@router.get(
    "/users/{userId}/morphology",
    operation_id="getUserMorphology",
    summary="Morphologie d'un utilisateur (Analytique → Utilisateurs)",
    description=(
        "Sert au service Analytique à normaliser les angles. Il n'y a aucune jointure entre schémas : "
        "Analytique appelle cette API avec le jeton de service."
    ),
    response_model=Morphology,
    responses={404: {"model": Error, "description": "Utilisateur inconnu."}},
)
def get_user_morphology(
    user_id: Annotated[uuid.UUID, Path(alias="userId", description="Identifiant de l'utilisateur.")], db: DbDep
) -> Morphology:
    user = db.get(Utilisateur, user_id)
    if user is None:
        raise AppError(404, "USER_NOT_FOUND", "Utilisateur inconnu.")
    return to_morphology(user)
