"""Environnement Alembic du service Auth.

- Se connecte avec le rôle SQL du service (propriétaire du schéma « utilisateurs »).
- Garde la table `alembic_version` DANS le schéma du service : chaque service a son propre
  historique de migrations, sans toucher au schéma des autres (étanchéité, ADR-001).
- Prend un verrou consultatif PostgreSQL : si plusieurs instances démarrent en même temps,
  une seule migre, les autres attendent puis constatent que tout est à jour.
"""

from alembic import context
from sqlalchemy import create_engine, pool, text

from app.config import get_settings
from app.models import SCHEMA, Base

target_metadata = Base.metadata
MIGRATION_LOCK_ID = 727_274_001  # arbitraire, mais fixe et propre à ce service


def include_name(name, type_, parent_names):
    if type_ == "schema":
        return name == SCHEMA  # ignore les autres schémas de la base
    return True


def run_migrations_offline() -> None:
    context.configure(
        url=get_settings().database_url.render_as_string(hide_password=False),
        target_metadata=target_metadata,
        literal_binds=True,
        version_table_schema=SCHEMA,
        include_schemas=True,
        include_name=include_name,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # Le rôle a `search_path = utilisateurs` : Alembic prendrait ce schéma pour le schéma par défaut
    # et le comparerait mal aux modèles (`alembic check` verrait des tables « à créer »). On force
    # donc `public` pour cette connexion ; tout est de toute façon qualifié par le nom du schéma.
    engine = create_engine(
        get_settings().database_url, poolclass=pool.NullPool, connect_args={"options": "-c search_path=public"}
    )
    with engine.connect() as connection:
        connection.execute(text("SELECT pg_advisory_lock(:id)"), {"id": MIGRATION_LOCK_ID})
        connection.commit()  # le verrou est lié à la session, pas à la transaction
        try:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                version_table_schema=SCHEMA,
                include_schemas=True,
                include_name=include_name,
            )
            with context.begin_transaction():
                context.run_migrations()
        finally:
            connection.rollback()
            connection.execute(text("SELECT pg_advisory_unlock(:id)"), {"id": MIGRATION_LOCK_ID})
            connection.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
