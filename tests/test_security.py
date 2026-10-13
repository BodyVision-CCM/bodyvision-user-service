import os
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import security
from app.config import Settings


def test_password_hash_roundtrip():
    h = security.hash_password("un-mot-de-passe-solide")
    assert h.startswith("$argon2id$")
    assert security.verify_password(h, "un-mot-de-passe-solide")
    assert not security.verify_password(h, "autre-chose")
    assert not security.verify_password("pas-un-hash", "x"), "un hash corrompu en base ne doit pas lever d'erreur"


def test_two_hashes_of_the_same_password_differ():
    assert security.hash_password("meme-mot-de-passe") != security.hash_password("meme-mot-de-passe")


def test_refresh_tokens_are_random_and_hashed():
    (t1, h1), (t2, h2) = security.new_refresh_token(), security.new_refresh_token()
    assert t1 != t2 and h1 != h2 and len(t1) >= 60
    assert security.hash_refresh_token(t1) == h1 != t1


def test_kid_is_stable_for_a_key_and_differs_between_keys(tmp_path):
    pem = security.generate_private_key_pem()
    assert security.JwtKeys(pem).kid == security.JwtKeys(pem).kid
    assert security.JwtKeys(pem).kid != security.JwtKeys(security.generate_private_key_pem()).kid


def test_weak_or_non_rsa_keys_are_refused():
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    with pytest.raises(ValueError, match="2048"):
        security.JwtKeys(weak)


def test_write_new_private_key_never_overwrites_and_is_private(tmp_path: Path):
    target = tmp_path / "sub" / "jwt.pem"
    security.write_new_private_key(target)
    first = target.read_bytes()
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
    security.write_new_private_key(target)  # deuxième démarrage simultané : ne doit rien écraser
    assert target.read_bytes() == first
    assert [p.name for p in target.parent.iterdir()] == ["jwt.pem"], "pas de fichier temporaire oublié"


def test_missing_key_without_autogenerate_fails_fast(monkeypatch, tmp_path):
    settings = Settings(
        db_password="x",
        internal_service_token="t" * 20,
        jwt_private_key_file=tmp_path / "absente.pem",
        jwt_autogenerate_keys=False,  # explicite : conftest l'active dans l'environnement pour les autres tests
    )
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    security.get_keys.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="JWT_AUTOGENERATE_KEYS"):
            security.get_keys()
    finally:
        security.get_keys.cache_clear()


def test_service_token_too_short_is_refused_at_startup():
    with pytest.raises(ValueError):
        Settings(db_password="x", internal_service_token="court")


def test_database_url_escapes_special_characters():
    url = Settings(db_password="p@ss:w/ord?#", internal_service_token="t" * 20).database_url
    assert url.password == "p@ss:w/ord?#"
    assert "p@ss:w/ord" not in url.render_as_string(hide_password=True)
    assert "%40" in url.render_as_string(hide_password=False), "le @ du mot de passe doit être encodé dans l'URL"
