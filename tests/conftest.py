"""Les tests tournent contre un VRAI PostgreSQL (pas de mock de base) : il faut DB_PASSWORD, DB_HOST...
dans l'environnement, comme pour l'application. Le plus simple : `make test` (PostgreSQL jetable dans Docker).

Les comptes créés utilisent le domaine @bodyvision-tests.dev et sont supprimés à la fin de la session.
"""

import os
import tempfile
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

if "DB_PASSWORD" not in os.environ:
    pytest.skip(
        "DB_PASSWORD absent : lancez `make test` (PostgreSQL jetable dans Docker), ou exportez DB_HOST, DB_PORT, "
        "DB_NAME, DB_USER, DB_PASSWORD vers un PostgreSQL déjà initialisé (voir README, section Tests).",
        allow_module_level=True,
    )

# Doit être fait AVANT d'importer l'application (la configuration est lue à l'import).
os.environ.setdefault("INTERNAL_SERVICE_TOKEN", "test-service-token-0123456789abcdef")
os.environ["JWT_PRIVATE_KEY_FILE"] = str(Path(tempfile.mkdtemp(prefix="bv-test-keys-")) / "jwt.pem")
os.environ["JWT_AUTOGENERATE_KEYS"] = "true"
os.environ.pop("JWT_PRIVATE_KEY", None)
os.environ["ENABLE_DOCS"] = "true"

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from tests.constants import PASSWORD, TEST_DOMAIN  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session", autouse=True)
def _database():
    """Applique les migrations (idempotent) puis nettoie les comptes de test à la fin."""
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(cfg, "head")
    yield
    from app.db import get_engine

    with get_engine().begin() as conn:
        conn.execute(text("DELETE FROM utilisateurs.utilisateur WHERE email LIKE :p"), {"p": f"%@{TEST_DOMAIN}"})


@pytest.fixture(scope="session")
def app():
    from app.main import app

    return app


@pytest.fixture(scope="session")
def client(app):
    with TestClient(app) as c:  # le `with` joue le lifespan (chargement de la clé de signature)
        yield c


@pytest.fixture(scope="session")
def settings():
    from app.config import get_settings

    return get_settings()


@pytest.fixture(scope="session")
def keys():
    from app.security import get_keys

    return get_keys()


@pytest.fixture
def db():
    from app.db import get_engine

    with get_engine().begin() as conn:
        yield conn


@pytest.fixture
def make_user(client):
    def _make(password: str = PASSWORD, email: str | None = None):
        email = email or f"t-{uuid.uuid4().hex[:12]}@{TEST_DOMAIN}"
        r = client.post("/v1/auth/register", json={"email": email, "password": password})
        assert r.status_code == 201, r.text
        tokens = r.json()
        return SimpleNamespace(
            email=email,
            password=password,
            access=tokens["accessToken"],
            refresh=tokens["refreshToken"],
            headers={"Authorization": f"Bearer {tokens['accessToken']}"},
        )

    return _make


@pytest.fixture
def user(make_user):
    return make_user()


@pytest.fixture
def service_headers(settings):
    return {"Authorization": f"Bearer {settings.internal_service_token.get_secret_value()}"}
