import logging
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter
from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import security
from app.config import Settings
from app.deps import DbDep, KeysDep, SettingsDep
from app.errors import VALIDATION_ERROR, AppError, Error, unauthorized
from app.models import JetonRafraichissement, Profil, Utilisateur
from app.schemas import Credentials, RefreshRequest, TokenPair

router = APIRouter(prefix="/v1/auth", tags=["auth"])
log = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _issue_tokens(
    db: Session, user: Utilisateur, settings: Settings, keys: security.JwtKeys, token_id: uuid.UUID | None = None
) -> TokenPair:
    """Crée un jeton d'accès (JWT) et un jeton de rafraîchissement (aléatoire, stocké haché).

    `token_id` : identifiant imposé au nouveau jeton de rafraîchissement (la rotation en a besoin pour renseigner
    `remplace_par` sur l'ancien). La ligne est écrite (flush) tout de suite, pour qu'une clé étrangère puisse la viser."""
    refresh, digest = security.new_refresh_token()
    db.add(
        JetonRafraichissement(
            id=token_id or uuid.uuid4(),
            utilisateur_id=user.id,
            empreinte=digest,
            expire_le=_now() + timedelta(days=settings.refresh_token_ttl_days),
        )
    )
    db.flush()
    return TokenPair(
        access_token=keys.sign_access_token(user.id, settings),
        refresh_token=refresh,
        expires_in=settings.access_token_ttl_seconds,
    )


@router.post(
    "/register",
    operation_id="register",
    summary="Créer un compte",
    description="Crée le compte et son profil vide, puis connecte directement l'utilisateur (renvoie les jetons).",
    status_code=201,
    response_model=TokenPair,
    responses={409: {"model": Error, "description": "Un compte existe déjà avec cet e-mail."}, **VALIDATION_ERROR},
)
def register(body: Credentials, db: DbDep, settings: SettingsDep, keys: KeysDep) -> TokenPair:
    email_taken = AppError(409, "EMAIL_ALREADY_REGISTERED", "Un compte existe déjà avec cet e-mail.")
    if db.scalar(select(Utilisateur.id).where(func.lower(Utilisateur.email) == body.email)) is not None:
        raise email_taken
    user = Utilisateur(email=body.email, mot_de_passe_hash=security.hash_password(body.password), profil=Profil())
    db.add(user)
    try:
        db.flush()
    except IntegrityError:  # deux inscriptions simultanées : l'index unique de la base tranche
        db.rollback()
        raise email_taken from None
    tokens = _issue_tokens(db, user, settings, keys)
    db.commit()
    return tokens


@router.post(
    "/login",
    operation_id="login",
    summary="Se connecter",
    response_model=TokenPair,
    responses={401: {"model": Error, "description": "E-mail ou mot de passe incorrect."}, **VALIDATION_ERROR},
)
def login(body: Credentials, db: DbDep, settings: SettingsDep, keys: KeysDep) -> TokenPair:
    # Même erreur et même durée que l'e-mail soit inconnu ou le mot de passe faux (pas d'énumération de comptes).
    invalid = unauthorized("INVALID_CREDENTIALS", "E-mail ou mot de passe incorrect.")
    user = db.scalar(select(Utilisateur).where(func.lower(Utilisateur.email) == body.email))
    if user is None:
        security.verify_dummy(body.password)
        raise invalid
    if not security.verify_password(user.mot_de_passe_hash, body.password):
        raise invalid
    if security.needs_rehash(user.mot_de_passe_hash):  # paramètres argon2 renforcés depuis l'inscription
        user.mot_de_passe_hash = security.hash_password(body.password)
    user.derniere_connexion = _now()
    db.execute(  # ménage : les jetons expirés ne servent plus à rien (les révoqués non expirés restent, cf. refresh)
        delete(JetonRafraichissement).where(
            JetonRafraichissement.utilisateur_id == user.id, JetonRafraichissement.expire_le < _now()
        )
    )
    tokens = _issue_tokens(db, user, settings, keys)
    db.commit()
    return tokens


@router.post(
    "/refresh",
    operation_id="refreshToken",
    summary="Renouveler le jeton d'accès",
    description=(
        "Échange un jeton de rafraîchissement contre une **nouvelle paire** de jetons : l'ancien jeton est "
        "révoqué (rotation). Rejouer un jeton déjà échangé **dans la fenêtre de tolérance** "
        "(`REFRESH_REUSE_INTERVAL_SECONDS`, 30 s par défaut : réponse perdue, deux appels simultanés) émet une nouvelle "
        "paire et révoque celle du premier appel, sans toucher aux autres sessions, **à condition que le jeton de "
        "remplacement n'ait pas encore servi**. **Sinon, ou au-delà**, c'est le signe d'un vol : toutes les sessions du compte sont révoquées et l'utilisateur doit se reconnecter."
    ),
    response_model=TokenPair,
    responses={
        401: {"model": Error, "description": "Jeton de rafraîchissement inconnu, expiré ou déjà utilisé."},
        **VALIDATION_ERROR,
    },
)
def refresh(body: RefreshRequest, db: DbDep, settings: SettingsDep, keys: KeysDep) -> TokenPair:
    digest = security.hash_refresh_token(body.refresh_token)
    owner_id = db.scalar(select(JetonRafraichissement.utilisateur_id).where(JetonRafraichissement.empreinte == digest))
    if owner_id is None:
        raise unauthorized("INVALID_REFRESH_TOKEN", "Jeton de rafraîchissement invalide.")
    # Les refresh d'un même compte passent l'un après l'autre : verrou sur la ligne de l'utilisateur d'abord (NO KEY
    # UPDATE : il ne bloque pas les insertions des tables qui le référencent), puis sur le jeton. Un ordre unique
    # évite les interblocages entre un rejeu toléré, une rotation et une purge.
    db.execute(select(Utilisateur.id).where(Utilisateur.id == owner_id).with_for_update(key_share=True))
    row = db.scalar(
        select(JetonRafraichissement)
        .where(JetonRafraichissement.empreinte == digest)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if row is None:
        raise unauthorized("INVALID_REFRESH_TOKEN", "Jeton de rafraîchissement invalide.")
    now = _now()
    if row.revoque_le is not None:
        window = timedelta(seconds=settings.refresh_reuse_interval_seconds)
        # Tolérance : jeton révoqué par ROTATION (remplace_par renseigné), encore dans la fenêtre, non expiré,
        # ET dont le successeur DIRECT est encore actif, c'est-à-dire n'a jamais servi. Si le successeur a déjà été
        # échangé, quelqu'un d'autre détient la suite de la chaîne : c'est un vol, pas une réponse perdue.
        # Un jeton révoqué par purge (remplace_par NULL) n'est jamais toléré.
        successor = None
        if row.remplace_par is not None and row.expire_le > now and now - row.revoque_le <= window:
            successor = db.get(JetonRafraichissement, row.remplace_par, with_for_update=True)
            if successor is not None and successor.revoque_le is not None:
                successor = None
        if successor is not None:
            user = db.get(Utilisateur, row.utilisateur_id)
            new_id = uuid.uuid4()
            tokens = _issue_tokens(db, user, settings, keys, token_id=new_id)
            # Tous les jetons qui visaient le successeur remplacé (rejeux déjà tolérés) visent désormais le nouveau.
            db.execute(
                update(JetonRafraichissement)
                .where(JetonRafraichissement.remplace_par == successor.id)
                .values(remplace_par=new_id)
                .execution_options(synchronize_session="fetch")
            )
            successor.revoque_le = now  # la paire du premier appel est remplacée par celle-ci
            successor.remplace_par = new_id
            db.commit()
            log.info("refresh token replay tolerated", extra={"userId": str(row.utilisateur_id)})
            return tokens
        db.execute(
            update(JetonRafraichissement)
            .where(JetonRafraichissement.utilisateur_id == row.utilisateur_id, JetonRafraichissement.revoque_le.is_(None))
            .values(revoque_le=now)
        )
        db.commit()
        log.warning("refresh token reuse detected, all sessions revoked", extra={"userId": str(row.utilisateur_id)})
        raise unauthorized("REFRESH_TOKEN_REUSED", "Jeton de rafraîchissement déjà utilisé : reconnectez-vous.")
    if row.expire_le <= now:
        raise unauthorized("REFRESH_TOKEN_EXPIRED", "Jeton de rafraîchissement expiré : reconnectez-vous.")
    user = db.get(Utilisateur, row.utilisateur_id)
    new_id = uuid.uuid4()
    tokens = _issue_tokens(db, user, settings, keys, token_id=new_id)
    row.revoque_le = now
    row.remplace_par = new_id  # rotation : cet ancien jeton est « remplacé », donc tolérable un court instant
    db.commit()
    return tokens
