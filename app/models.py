"""Modèles SQLAlchemy du schéma « utilisateurs ».

Ils reproduisent exactement le DDL du ticket de modélisation (db/10_utilisateurs.sql) : mêmes
tables, mêmes contraintes (mêmes noms), mêmes index. Les migrations Alembic les créent ; un
test vérifie que modèles et base ne divergent pas (`alembic check`).
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    MetaData,
    Numeric,
    SmallInteger,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

SCHEMA = "utilisateurs"  # fixé par l'ADR-001 : un schéma par service


class Base(DeclarativeBase):
    metadata = MetaData(schema=SCHEMA)


class Utilisateur(Base):
    __tablename__ = "utilisateur"
    __table_args__ = (
        CheckConstraint("position('@' IN email) > 1", name="utilisateur_email_check"),
        # E-mail unique sans tenir compte de la casse.
        Index("utilisateur_email_uq", text("lower(email)"), unique=True),
        {"comment": "Compte utilisateur (authentification)."},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    email: Mapped[str] = mapped_column(Text)
    mot_de_passe_hash: Mapped[str] = mapped_column(Text, comment="Empreinte argon2 du mot de passe.")
    nom_affichage: Mapped[str | None] = mapped_column(Text)
    cree_le: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    derniere_connexion: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    profil: Mapped["Profil | None"] = relationship(
        back_populates="utilisateur", uselist=False, cascade="all, delete-orphan", passive_deletes=True, lazy="joined"
    )


class Profil(Base):
    __tablename__ = "profil"
    __table_args__ = (
        CheckConstraint("taille_cm BETWEEN 100 AND 250", name="profil_taille_cm_check"),
        CheckConstraint("poids_kg BETWEEN 20 AND 300", name="profil_poids_kg_check"),
        CheckConstraint("niveau IN ('BEGINNER', 'INTERMEDIATE', 'ADVANCED')", name="profil_niveau_check"),
        CheckConstraint("mode_envoi IN ('WIFI_ONLY', 'ANY_NETWORK', 'MANUAL')", name="profil_mode_envoi_check"),
        {
            "comment": "Morphologie et réglages ; sert à normaliser les angles (endpoint interne morphologie)."
        },
    )

    utilisateur_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey(f"{SCHEMA}.utilisateur.id", ondelete="CASCADE"), primary_key=True
    )
    taille_cm: Mapped[int | None] = mapped_column(SmallInteger)
    poids_kg: Mapped[float | None] = mapped_column(Numeric(5, 2, asdecimal=False))
    niveau: Mapped[str | None] = mapped_column(Text)
    qualite_analyse: Mapped[str] = mapped_column(
        Text, server_default=text("'640x480@30'"), comment="Qualité d'analyse choisie (défaut 640x480@30, spike SCRUM-22)."
    )
    mode_envoi: Mapped[str] = mapped_column(Text, server_default=text("'WIFI_ONLY'"))
    modifie_le: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    utilisateur: Mapped[Utilisateur] = relationship(back_populates="profil")


class JetonRafraichissement(Base):
    __tablename__ = "jeton_rafraichissement"
    __table_args__ = (
        UniqueConstraint("empreinte", name="jeton_rafraichissement_empreinte_key"),
        CheckConstraint("expire_le > cree_le", name="jeton_rafraichissement_check"),
        Index("jeton_rafraichissement_utilisateur_idx", "utilisateur_id"),
        {"comment": "Jetons de rafraîchissement (empreinte seulement), révocables."},
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, server_default=text("gen_random_uuid()"))
    utilisateur_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey(f"{SCHEMA}.utilisateur.id", ondelete="CASCADE"))
    empreinte: Mapped[str] = mapped_column(Text)  # SHA-256 du jeton ; le jeton lui-même n'est jamais stocké
    cree_le: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expire_le: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoque_le: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
