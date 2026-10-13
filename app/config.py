"""Configuration du service, lue depuis les variables d'environnement.

Aucune valeur secrète n'a de défaut : si DB_PASSWORD ou INTERNAL_SERVICE_TOKEN manque,
le service refuse de démarrer (plutôt que de tourner avec un secret par défaut).
"""

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import URL


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    # --- Base de données (rôle SQL propre au service : accès limité au schéma "utilisateurs")
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "bodyvision"
    db_user: str = "bv_utilisateurs"
    db_password: SecretStr
    db_pool_size: int = Field(5, ge=1)
    db_max_overflow: int = Field(5, ge=0)

    # --- Jetons
    jwt_issuer: str = "bodyvision-auth"
    jwt_audience: str = "bodyvision"
    # Clé privée RSA (PEM). Soit un fichier, soit le PEM en variable (\n littéraux acceptés).
    jwt_private_key_file: Path = Path("/run/keys/jwt_private.pem")
    jwt_private_key: SecretStr | None = None
    # Dev uniquement : crée la paire de clés au premier démarrage si le fichier est absent.
    jwt_autogenerate_keys: bool = False
    access_token_ttl_seconds: int = Field(900, ge=60)
    refresh_token_ttl_days: int = Field(30, ge=1)

    # --- Appels service-à-service (ex. Analytique -> /internal/users/{id}/morphology)
    internal_service_token: SecretStr = Field(min_length=16)

    # --- Divers
    log_level: str = "INFO"
    enable_docs: bool = True  # Swagger UI (/docs), ReDoc (/redoc), /openapi.json

    @property
    def database_url(self) -> URL:
        # URL.create échappe correctement les caractères spéciaux du mot de passe.
        return URL.create(
            "postgresql+psycopg",
            username=self.db_user,
            password=self.db_password.get_secret_value(),
            host=self.db_host,
            port=self.db_port,
            database=self.db_name,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]  # les champs obligatoires viennent de l'environnement
