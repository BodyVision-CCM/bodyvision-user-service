"""Schéma « utilisateurs » : utilisateur, profil, jeton_rafraichissement

Équivalent exact du DDL de référence du ticket de modélisation (db/10_utilisateurs.sql).
Le schéma lui-même et le rôle propriétaire sont créés avant, par l'administrateur
(dépôt infra-compose : postgres/init/00_roles_schemas.sh) : le service n'a pas le droit de créer un schéma.

Revision ID: 0001
Revises:
"""

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

S = "utilisateurs"


def upgrade() -> None:
    op.create_table(
        "utilisateur",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("mot_de_passe_hash", sa.Text(), nullable=False, comment="Empreinte argon2 du mot de passe."),
        sa.Column("nom_affichage", sa.Text(), nullable=True),
        sa.Column("cree_le", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("derniere_connexion", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("position('@' IN email) > 1", name="utilisateur_email_check"),
        sa.PrimaryKeyConstraint("id"),
        schema=S,
        comment="Compte utilisateur (authentification).",
    )
    op.create_index("utilisateur_email_uq", "utilisateur", [sa.text("lower(email)")], unique=True, schema=S)

    op.create_table(
        "profil",
        sa.Column("utilisateur_id", sa.Uuid(), nullable=False),
        sa.Column("taille_cm", sa.SmallInteger(), nullable=True),
        sa.Column("poids_kg", sa.Numeric(5, 2), nullable=True),
        sa.Column("niveau", sa.Text(), nullable=True),
        sa.Column(
            "qualite_analyse",
            sa.Text(),
            server_default=sa.text("'640x480@30'"),
            nullable=False,
            comment="Qualité d'analyse choisie (défaut 640x480@30, spike SCRUM-22).",
        ),
        sa.Column("mode_envoi", sa.Text(), server_default=sa.text("'WIFI_ONLY'"), nullable=False),
        sa.Column("modifie_le", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("taille_cm BETWEEN 100 AND 250", name="profil_taille_cm_check"),
        sa.CheckConstraint("poids_kg BETWEEN 20 AND 300", name="profil_poids_kg_check"),
        sa.CheckConstraint("niveau IN ('BEGINNER', 'INTERMEDIATE', 'ADVANCED')", name="profil_niveau_check"),
        sa.CheckConstraint("mode_envoi IN ('WIFI_ONLY', 'ANY_NETWORK', 'MANUAL')", name="profil_mode_envoi_check"),
        sa.ForeignKeyConstraint(["utilisateur_id"], [f"{S}.utilisateur.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("utilisateur_id"),
        schema=S,
        comment="Morphologie et réglages ; sert à normaliser les angles (endpoint interne morphologie).",
    )

    op.create_table(
        "jeton_rafraichissement",
        sa.Column("id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("utilisateur_id", sa.Uuid(), nullable=False),
        sa.Column("empreinte", sa.Text(), nullable=False),
        sa.Column("cree_le", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("expire_le", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoque_le", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("expire_le > cree_le", name="jeton_rafraichissement_check"),
        sa.ForeignKeyConstraint(["utilisateur_id"], [f"{S}.utilisateur.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("empreinte", name="jeton_rafraichissement_empreinte_key"),
        schema=S,
        comment="Jetons de rafraîchissement (empreinte seulement), révocables.",
    )
    op.create_index(
        "jeton_rafraichissement_utilisateur_idx", "jeton_rafraichissement", ["utilisateur_id"], schema=S
    )


def downgrade() -> None:
    op.drop_table("jeton_rafraichissement", schema=S)
    op.drop_table("profil", schema=S)
    op.drop_index("utilisateur_email_uq", table_name="utilisateur", schema=S)
    op.drop_table("utilisateur", schema=S)
