"""Rotation du jeton de rafraîchissement : distinguer « révoqué par rotation » de « révoqué par purge »

Ajoute `jeton_rafraichissement.remplace_par` : identifiant du jeton successeur, renseigné UNIQUEMENT quand le jeton
est révoqué parce qu'il a été échangé contre une nouvelle paire (rotation normale).

- `remplace_par` renseigné  -> révoqué par rotation : un rejeu dans la courte fenêtre de tolérance
  (REFRESH_REUSE_INTERVAL_SECONDS) est une réponse perdue ou un double appel, pas un vol.
- `revoque_le` renseigné et `remplace_par` NULL -> révoqué par purge (vol détecté) : jamais toléré.
  Les jetons révoqués avant cette migration n'ont pas de successeur : ils sont donc traités comme révoqués par
  purge, ce qui conserve le comportement d'avant (le plus strict).

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

S = "utilisateurs"


def upgrade() -> None:
    op.add_column(
        "jeton_rafraichissement",
        sa.Column(
            "remplace_par",
            sa.Uuid(),
            nullable=True,
            comment="Jeton successeur si celui-ci a été révoqué par rotation ; NULL sinon (actif, ou révoqué par purge).",
        ),
        schema=S,
    )
    op.create_foreign_key(
        "jeton_rafraichissement_remplace_par_fkey",
        "jeton_rafraichissement",
        "jeton_rafraichissement",
        ["remplace_par"],
        ["id"],
        source_schema=S,
        referent_schema=S,
        ondelete="SET NULL",
    )
    # Un jeton qui a un successeur est forcément révoqué.
    op.create_check_constraint(
        "jeton_rafraichissement_remplace_par_check",
        "jeton_rafraichissement",
        "remplace_par IS NULL OR revoque_le IS NOT NULL",
        schema=S,
    )
    # Sert la suppression du successeur (ON DELETE SET NULL) sans balayer toute la table.
    op.create_index(
        "jeton_rafraichissement_remplace_par_idx",
        "jeton_rafraichissement",
        ["remplace_par"],
        schema=S,
        postgresql_where=sa.text("remplace_par IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("jeton_rafraichissement_remplace_par_idx", table_name="jeton_rafraichissement", schema=S)
    op.drop_constraint("jeton_rafraichissement_remplace_par_check", "jeton_rafraichissement", schema=S, type_="check")
    op.drop_constraint("jeton_rafraichissement_remplace_par_fkey", "jeton_rafraichissement", schema=S, type_="foreignkey")
    op.drop_column("jeton_rafraichissement", "remplace_par", schema=S)