import base64
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import text


def _claims(settings, sub, **over):
    now = datetime.now(timezone.utc)
    c = {
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "sub": str(sub),
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": uuid.uuid4().hex,
    }
    c.update(over)
    return c


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _user_id(client, user):
    return client.get("/v1/users/me", headers=user.headers).json()["id"]


# ------------------------------------------------------------------ lecture du profil


def test_get_me_returns_defaults_for_a_new_account(client, user):
    r = client.get("/v1/users/me", headers=user.headers)
    assert r.status_code == 200
    body = r.json()
    uuid.UUID(body["id"])
    assert body["email"] == user.email
    assert body["displayName"] is None
    assert body["heightCm"] is None and body["weightKg"] is None and body["level"] is None
    assert body["settings"] == {"analysisQuality": "640x480@30", "uploadMode": "WIFI_ONLY"}
    assert "password" not in json.dumps(body).lower()


# ------------------------------------------------------------------ jetons d'accès refusés


def test_missing_token_is_a_401_in_the_contract_format(client):
    r = client.get("/v1/users/me")
    assert r.status_code == 401
    assert r.json()["code"] == "UNAUTHENTICATED"
    assert r.headers["www-authenticate"] == "Bearer"


def test_garbage_token_is_rejected(client):
    r = client.get("/v1/users/me", headers=_bearer("pas.un.jwt"))
    assert r.status_code == 401 and r.json()["code"] == "INVALID_TOKEN"


def test_expired_token_is_rejected_with_a_specific_code(client, keys, settings, user):
    sub = _user_id(client, user)
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        _claims(settings, sub, iat=now - timedelta(hours=2), exp=now - timedelta(hours=1)),
        keys._private,
        algorithm="RS256",
        headers={"kid": keys.kid},
    )
    r = client.get("/v1/users/me", headers=_bearer(token))
    assert r.status_code == 401 and r.json()["code"] == "TOKEN_EXPIRED"


def test_token_signed_by_another_key_is_rejected(client, settings, user):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(_claims(settings, _user_id(client, user)), other, algorithm="RS256")
    assert client.get("/v1/users/me", headers=_bearer(token)).json()["code"] == "INVALID_TOKEN"


def test_alg_none_token_is_rejected(client, settings, user):
    token = jwt.encode(_claims(settings, _user_id(client, user)), None, algorithm="none")
    assert client.get("/v1/users/me", headers=_bearer(token)).status_code == 401


def test_hs256_token_signed_with_the_public_key_is_rejected(client, keys, settings, user):
    """Attaque classique de confusion d'algorithme : on signe en HMAC avec la clé PUBLIQUE (connue de tous)
    en espérant que le serveur la prenne pour un secret. Seul RS256 est accepté."""
    public_pem = keys.public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=")

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    claims = _claims(settings, _user_id(client, user))
    claims["iat"], claims["exp"] = int(time.time()), int(time.time()) + 300
    payload = b64(json.dumps(claims).encode())
    signature = b64(hmac.new(public_pem, header + b"." + payload, hashlib.sha256).digest())
    token = (header + b"." + payload + b"." + signature).decode()
    assert client.get("/v1/users/me", headers=_bearer(token)).status_code == 401


def test_wrong_audience_or_issuer_is_rejected(client, keys, settings, user):
    sub = _user_id(client, user)
    for over in ({"aud": "autre-api"}, {"iss": "autre-emetteur"}):
        token = jwt.encode(_claims(settings, sub, **over), keys._private, algorithm="RS256")
        assert client.get("/v1/users/me", headers=_bearer(token)).status_code == 401, over


def test_token_without_expiry_is_rejected(client, keys, settings, user):
    claims = _claims(settings, _user_id(client, user))
    del claims["exp"]
    token = jwt.encode(claims, keys._private, algorithm="RS256")
    assert client.get("/v1/users/me", headers=_bearer(token)).status_code == 401


def test_token_of_a_deleted_account_is_rejected(client, db, user):
    db.execute(text("DELETE FROM utilisateurs.utilisateur WHERE email = :e"), {"e": user.email})
    db.commit()
    r = client.get("/v1/users/me", headers=user.headers)
    assert r.status_code == 401 and r.json()["code"] == "INVALID_TOKEN"


# ------------------------------------------------------------------ mise à jour du profil


def test_patch_is_partial(client, user):
    r = client.patch("/v1/users/me", headers=user.headers, json={"heightCm": 180})
    assert r.status_code == 200
    assert r.json()["heightCm"] == 180 and r.json()["weightKg"] is None

    r = client.patch(
        "/v1/users/me",
        headers=user.headers,
        json={"weightKg": 80.5, "level": "INTERMEDIATE", "displayName": "Brice", "settings": {"uploadMode": "MANUAL"}},
    )
    body = r.json()
    assert body["heightCm"] == 180, "un champ non envoyé ne doit pas bouger"
    assert body["weightKg"] == 80.5 and body["level"] == "INTERMEDIATE" and body["displayName"] == "Brice"
    assert body["settings"] == {"analysisQuality": "640x480@30", "uploadMode": "MANUAL"}
    assert client.get("/v1/users/me", headers=user.headers).json() == body, "la modification est bien persistée"


def test_patch_null_clears_morphology_and_name(client, user):
    client.patch("/v1/users/me", headers=user.headers, json={"heightCm": 175, "displayName": "X"})
    r = client.patch("/v1/users/me", headers=user.headers, json={"heightCm": None, "displayName": None})
    assert r.json()["heightCm"] is None and r.json()["displayName"] is None


def test_patch_rejects_out_of_range_and_unknown_values(client, user):
    for bad in (
        {"heightCm": 50},
        {"heightCm": 300},
        {"weightKg": 5},
        {"level": "EXPERT"},
        {"settings": {"uploadMode": "SOMETIMES"}},
        {"settings": {"uploadMode": None}},
        {"settings": None},
        {"settings": {"analysisQuality": "x" * 33}},
    ):
        r = client.patch("/v1/users/me", headers=user.headers, json=bad)
        assert r.status_code == 422, bad
        assert r.json()["code"] == "VALIDATION_ERROR"


def test_patch_can_resend_the_get_response_and_never_changes_id_or_email(client, user):
    current = client.get("/v1/users/me", headers=user.headers).json()
    assert client.patch("/v1/users/me", headers=user.headers, json=current).status_code == 200
    r = client.patch(
        "/v1/users/me", headers=user.headers, json={"email": "pirate@bodyvision-tests.dev", "id": str(uuid.uuid4())}
    )
    assert r.json()["email"] == user.email and r.json()["id"] == current["id"]


def test_patch_requires_authentication(client):
    assert client.patch("/v1/users/me", json={"heightCm": 180}).status_code == 401
