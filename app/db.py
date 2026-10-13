from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings


@lru_cache
def get_engine() -> Engine:
    s = get_settings()
    return create_engine(
        s.database_url,
        pool_pre_ping=True,  # une connexion coupée (redémarrage de Postgres) est retentée proprement
        pool_size=s.db_pool_size,
        max_overflow=s.db_max_overflow,
        connect_args={"application_name": "bodyvision-auth"},
    )


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """Une session par requête. Sans commit explicite, tout est annulé à la fermeture."""
    with get_sessionmaker()() as session:
        yield session
