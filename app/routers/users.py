from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends

from app.deps import DbDep, get_current_user
from app.errors import Error
from app.models import Profil, Utilisateur
from app.schemas import UserProfile, UserProfileUpdate, to_user_profile

router = APIRouter(
    prefix="/v1/users",
    tags=["users"],
    responses={401: {"model": Error, "description": "Jeton d'accès absent, invalide ou expiré."}},
)

CurrentUser = Annotated[Utilisateur, Depends(get_current_user)]


@router.get(
    "/me",
    operation_id="getMe",
    summary="Profil courant",
    description="Identité, morphologie et réglages de l'utilisateur connecté (écran Profil).",
    response_model=UserProfile,
)
def get_me(user: CurrentUser) -> UserProfile:
    return to_user_profile(user)


@router.patch(
    "/me",
    operation_id="updateMe",
    summary="Mettre à jour le profil",
    description=(
        "Mise à jour **partielle** : seuls les champs envoyés sont modifiés. `null` efface le nom ou la "
        "morphologie ; un réglage (`settings`) ne peut pas être effacé. `id` et `email` sont en lecture seule "
        "(ignorés s'ils sont envoyés), on peut donc renvoyer tel quel le résultat de `GET /v1/users/me`."
    ),
    response_model=UserProfile,
)
def update_me(body: UserProfileUpdate, user: CurrentUser, db: DbDep) -> UserProfile:
    sent = body.model_fields_set
    if user.profil is None:  # ne devrait pas arriver (créé à l'inscription), mais on se répare
        user.profil = Profil()
    p = user.profil
    if "display_name" in sent:
        user.nom_affichage = body.display_name
    if "height_cm" in sent:
        p.taille_cm = body.height_cm
    if "weight_kg" in sent:
        p.poids_kg = body.weight_kg
    if "level" in sent:
        p.niveau = body.level
    if body.settings is not None:
        if "analysis_quality" in body.settings.model_fields_set:
            p.qualite_analyse = body.settings.analysis_quality
        if "upload_mode" in body.settings.model_fields_set:
            p.mode_envoi = body.settings.upload_mode
    p.modifie_le = datetime.now(timezone.utc)
    db.commit()
    return to_user_profile(user)
