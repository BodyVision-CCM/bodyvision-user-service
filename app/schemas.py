"""Schémas d'entrée/sortie. Les noms et les champs reprennent ceux de openapi.yaml (contrat v0.3) :
Credentials, TokenPair, Morphology, UserProfile. Un test vérifie cette conformité."""

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

from app.models import Utilisateur

Level = Literal["BEGINNER", "INTERMEDIATE", "ADVANCED"]
UploadMode = Literal["WIFI_ONLY", "ANY_NETWORK", "MANUAL"]


class CamelModel(BaseModel):
    """JSON en camelCase (comme le contrat), attributs Python en snake_case."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="ignore")


class Credentials(CamelModel):
    email: EmailStr
    password: str = Field(min_length=10, max_length=128, json_schema_extra={"format": "password"})

    @field_validator("email")
    @classmethod
    def _normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class RefreshRequest(CamelModel):
    refresh_token: str = Field(min_length=1, max_length=512)


class TokenPair(CamelModel):
    access_token: str
    refresh_token: str
    expires_in: int = Field(examples=[900], description="Durée de validité du jeton d'accès, en secondes.")


class Morphology(CamelModel):
    height_cm: int | None = Field(None, ge=100, le=250)
    weight_kg: float | None = Field(None, ge=20, le=300)
    level: Level | None = None


class UserSettings(CamelModel):
    analysis_quality: str = Field(examples=["640x480@30"], max_length=32)
    upload_mode: UploadMode = "WIFI_ONLY"


class UserProfile(Morphology):
    id: uuid.UUID
    email: EmailStr
    display_name: str | None = None
    settings: UserSettings


# --- Mise à jour partielle (PATCH) : seuls les champs envoyés sont modifiés ; null efface
#     la morphologie ou le nom, mais un réglage ne peut pas être effacé.


class UserSettingsUpdate(CamelModel):
    analysis_quality: str | None = Field(None, max_length=32)
    upload_mode: UploadMode | None = None

    @model_validator(mode="after")
    def _no_null_setting(self):
        for name in self.model_fields_set:
            if getattr(self, name) is None:
                raise ValueError(f"{to_camel(name)} ne peut pas être null.")
        return self


class UserProfileUpdate(Morphology):
    display_name: str | None = Field(None, max_length=100)
    settings: UserSettingsUpdate | None = None

    @model_validator(mode="after")
    def _no_null_settings(self):
        if "settings" in self.model_fields_set and self.settings is None:
            raise ValueError("settings ne peut pas être null.")
        return self


def to_user_profile(user: Utilisateur) -> UserProfile:
    p = user.profil
    return UserProfile(
        id=user.id,
        email=user.email,
        display_name=user.nom_affichage,
        height_cm=p.taille_cm if p else None,
        weight_kg=p.poids_kg if p else None,
        level=p.niveau if p else None,
        settings=UserSettings(
            analysis_quality=p.qualite_analyse if p else "640x480@30",
            upload_mode=p.mode_envoi if p else "WIFI_ONLY",
        ),
    )


def to_morphology(user: Utilisateur) -> Morphology:
    p = user.profil
    return Morphology(
        height_cm=p.taille_cm if p else None, weight_kg=p.poids_kg if p else None, level=p.niveau if p else None
    )
