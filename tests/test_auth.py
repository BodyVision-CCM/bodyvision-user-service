import hashlib
import uuid

from sqlalchemy import text

from tests.constants import PASSWORD, TEST_DOMAIN


def test_register_returns_a_token_pair(client):
    r = client.post("/v1/auth/register", json={"email": f"a1@{TEST_DOMAIN}", "password": PASSWORD})
    assert r.status_code == 201
    body = r.json()
    assert set(body) == {"accessToken", "refreshToken", "expiresIn"}
    assert body["expiresIn"] == 900
    assert body["accessToken"] != body["refreshToken"]


def test_register_creates_an_empty_profile(client, user):
    me = client.get("/v1/users/me", headers=user.headers)
    assert me.status_code == 200
    assert me.json()["email"] == user.email


def test_register_duplicate_email_is_a_409_whatever_the_case(client, user):
    r = client.post("/v1/auth/register", json={"email": user.email.upper(), "password": PASSWORD})
    assert r.status_code == 409
    body = r.json()
    assert body["code"] == "EMAIL_ALREADY_REGISTERED"
    assert body["traceId"] == r.headers["x-request-id"]


def test_email_is_normalized_to_lowercase(client, make_user):
    u = make_user(email=f"MiXeD-{uuid.uuid4().hex[:8]}@{TEST_DOMAIN}")
    assert u.email != u.email.lower()  # envoyé avec des majuscules ...
    r = client.post("/v1/auth/login", json={"email": u.email.lower(), "password": u.password})
    assert r.status_code == 200  # ... retrouvé en minuscules


def test_register_validation_errors_use_the_contract_error_format(client):
    r = client.post("/v1/auth/register", json={"email": f"v1@{TEST_DOMAIN}", "password": "court"})
    assert r.status_code == 422
    body = r.json()
    assert body["code"] == "VALIDATION_ERROR"
    assert "password" in body["message"]
    assert "court" not in body["message"], "la valeur reçue (mot de passe) ne doit jamais être renvoyée"
    assert client.post("/v1/auth/register", json={"email": "pas-un-email", "password": PASSWORD}).status_code == 422
    assert client.post("/v1/auth/register", json={}).status_code == 422


def test_password_is_stored_as_argon2id_never_in_clear(db, user):
    stored = db.execute(
        text("SELECT mot_de_passe_hash FROM utilisateurs.utilisateur WHERE email = :e"), {"e": user.email}
    ).scalar_one()
    assert stored.startswith("$argon2id$")
    assert user.password not in stored


def test_login_ok(client, user):
    r = client.post("/v1/auth/login", json={"email": user.email, "password": user.password})
    assert r.status_code == 200
    assert r.json()["expiresIn"] == 900


def test_login_wrong_password_and_unknown_email_are_indistinguishable(client, user):
    wrong = client.post("/v1/auth/login", json={"email": user.email, "password": "mauvais-mot-de-passe"})
    unknown = client.post("/v1/auth/login", json={"email": f"inconnu@{TEST_DOMAIN}", "password": PASSWORD})
    assert wrong.status_code == unknown.status_code == 401
    a, b = wrong.json(), unknown.json()
    assert a["code"] == b["code"] == "INVALID_CREDENTIALS"
    assert a["message"] == b["message"]
    assert wrong.headers["www-authenticate"] == "Bearer"


def test_login_updates_last_connection(client, db, user):
    client.post("/v1/auth/login", json={"email": user.email, "password": user.password})
    last = db.execute(
        text("SELECT derniere_connexion FROM utilisateurs.utilisateur WHERE email = :e"), {"e": user.email}
    ).scalar_one()
    assert last is not None


def test_refresh_rotates_the_token(client, user):
    r = client.post("/v1/auth/refresh", json={"refreshToken": user.refresh})
    assert r.status_code == 200
    new = r.json()
    assert new["refreshToken"] != user.refresh
    # le nouveau jeton d'accès fonctionne
    assert client.get("/v1/users/me", headers={"Authorization": f"Bearer {new['accessToken']}"}).status_code == 200


def test_reusing_a_consumed_refresh_token_revokes_every_session(client, user):
    new = client.post("/v1/auth/refresh", json={"refreshToken": user.refresh}).json()
    # l'ancien jeton est rejoué (vol possible) ...
    replay = client.post("/v1/auth/refresh", json={"refreshToken": user.refresh})
    assert replay.status_code == 401
    assert replay.json()["code"] == "REFRESH_TOKEN_REUSED"
    # ... donc le jeton légitime, pourtant plus récent, est lui aussi révoqué
    assert client.post("/v1/auth/refresh", json={"refreshToken": new["refreshToken"]}).status_code == 401


def test_refresh_with_unknown_token(client):
    r = client.post("/v1/auth/refresh", json={"refreshToken": "x" * 64})
    assert r.status_code == 401
    assert r.json()["code"] == "INVALID_REFRESH_TOKEN"


def test_refresh_with_expired_token(client, db, user):
    digest = hashlib.sha256(user.refresh.encode()).hexdigest()
    db.execute(
        text(
            "UPDATE utilisateurs.jeton_rafraichissement "
            "SET cree_le = now() - interval '2 days', expire_le = now() - interval '1 day' WHERE empreinte = :d"
        ),
        {"d": digest},
    )
    db.commit()
    r = client.post("/v1/auth/refresh", json={"refreshToken": user.refresh})
    assert r.status_code == 401
    assert r.json()["code"] == "REFRESH_TOKEN_EXPIRED"


def test_only_the_hash_of_the_refresh_token_is_stored(db, user):
    rows = db.execute(text("SELECT empreinte FROM utilisateurs.jeton_rafraichissement")).scalars().all()
    assert user.refresh not in rows
    assert hashlib.sha256(user.refresh.encode()).hexdigest() in rows


def test_an_access_token_cannot_be_used_as_a_refresh_token(client, user):
    # Un JWT dépasse la borne de taille d'un jeton de rafraîchissement (512) : rejeté dès la validation (422).
    # Ce qui compte ici : quel que soit le code de refus, aucun jeton n'est délivré.
    r = client.post("/v1/auth/refresh", json={"refreshToken": user.access})
    assert r.status_code in (401, 422)
    assert "accessToken" not in r.json()
