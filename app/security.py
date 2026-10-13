"""Mots de passe (argon2id), clés RSA, jetons d'accès JWT (RS256) et jetons de rafraîchissement."""

import base64
import hashlib
import json
import os
import secrets
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import Settings, get_settings

# --------------------------------------------------------------------------- mots de passe

_hasher = PasswordHasher()  # argon2id, paramètres par défaut de la bibliothèque
# Hash factice : vérifié quand l'e-mail est inconnu, pour que "e-mail inconnu" et "mauvais mot
# de passe" prennent le même temps (sinon le temps de réponse révèle si le compte existe).
_DUMMY_HASH = _hasher.hash("mot-de-passe-factice")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def verify_dummy(password: str) -> None:
    verify_password(_DUMMY_HASH, password)


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


# --------------------------------------------------------------------------- jetons de rafraîchissement


def new_refresh_token() -> tuple[str, str]:
    """Renvoie (jeton à donner au client, empreinte à stocker). Seule l'empreinte est conservée."""
    token = secrets.token_urlsafe(48)
    return token, hash_refresh_token(token)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# --------------------------------------------------------------------------- clés RSA / JWT


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def generate_private_key_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


class JwtKeys:
    """Paire de clés RSA : signe les jetons d'accès et publie la clé publique (JWKS)."""

    def __init__(self, private_pem: bytes):
        key = serialization.load_pem_private_key(private_pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("La clé privée JWT doit être une clé RSA.")
        if key.key_size < 2048:
            raise ValueError("La clé RSA doit faire au moins 2048 bits.")
        self._private = key
        self.public = key.public_key()
        numbers = self.public.public_numbers()
        n = _b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))
        e = _b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
        # kid = empreinte RFC 7638 : change si et seulement si la clé change.
        thumbprint = json.dumps({"e": e, "kty": "RSA", "n": n}, separators=(",", ":"), sort_keys=True)
        self.kid = _b64url(hashlib.sha256(thumbprint.encode()).digest())
        self.jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid, "n": n, "e": e}

    def sign_access_token(self, user_id: uuid.UUID, settings: Settings) -> str:
        now = datetime.now(timezone.utc)
        claims = {
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
            "sub": str(user_id),
            "iat": now,
            "exp": now + timedelta(seconds=settings.access_token_ttl_seconds),
            "jti": uuid.uuid4().hex,
        }
        return jwt.encode(claims, self._private, algorithm="RS256", headers={"kid": self.kid})

    def decode_access_token(self, token: str, settings: Settings) -> dict:
        """Lève jwt.ExpiredSignatureError ou jwt.InvalidTokenError. Seul RS256 est accepté."""
        return jwt.decode(
            token,
            self.public,
            algorithms=["RS256"],
            audience=settings.jwt_audience,
            issuer=settings.jwt_issuer,
            leeway=5,
            options={"require": ["exp", "iat", "sub", "jti"]},
        )


def write_new_private_key(path: Path) -> None:
    """Écrit une nouvelle clé sans jamais écraser un fichier existant (création atomique) :
    si deux processus démarrent en même temps, un seul gagne et l'autre relit le fichier."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".jwt-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(generate_private_key_pem())
        os.chmod(tmp, 0o600)
        try:
            os.link(tmp, path)  # échoue si le fichier existe déjà
        except FileExistsError:
            pass
    finally:
        os.unlink(tmp)


@lru_cache
def get_keys() -> JwtKeys:
    s = get_settings()
    if s.jwt_private_key is not None:
        return JwtKeys(s.jwt_private_key.get_secret_value().replace("\\n", "\n").encode())
    path = s.jwt_private_key_file
    if not path.exists():
        if not s.jwt_autogenerate_keys:
            raise RuntimeError(
                f"Clé privée JWT introuvable ({path}). Fournissez JWT_PRIVATE_KEY_FILE ou JWT_PRIVATE_KEY, "
                "ou activez JWT_AUTOGENERATE_KEYS=true (développement uniquement)."
            )
        write_new_private_key(path)
    return JwtKeys(path.read_bytes())
