import hashlib
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

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


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _age_revocation(db, token: str, seconds: int) -> None:
    """Recule `revoque_le` (et les dates liées) pour simuler un rejeu tardif."""
    db.execute(
        text(
            "UPDATE utilisateurs.jeton_rafraichissement "
            "SET revoque_le = now() - make_interval(secs => :s) WHERE empreinte = :d"
        ),
        {"s": seconds, "d": _digest(token)},
    )
    db.commit()


def _refresh(client, token: str):
    return client.post("/v1/auth/refresh", json={"refreshToken": token})


def _login(client, user):
    r = client.post("/v1/auth/login", json={"email": user.email, "password": user.password})
    assert r.status_code == 200, r.text
    return r.json()


def test_replaying_a_rotated_token_inside_the_window_issues_a_new_pair(client, db, user):
    first = _refresh(client, user.refresh).json()
    replay = _refresh(client, user.refresh)  # réponse perdue : le client rejoue l'ancien jeton
    assert replay.status_code == 200
    second = replay.json()
    assert second["refreshToken"] not in (user.refresh, first["refreshToken"])
    # la paire du premier appel est révoquée (remplacée par celle du rejeu) ; celle du rejeu fonctionne
    revoked = db.execute(
        text("SELECT revoque_le IS NOT NULL FROM utilisateurs.jeton_rafraichissement WHERE empreinte = :d"),
        {"d": _digest(first["refreshToken"])},
    ).scalar_one()
    assert revoked
    assert client.get("/v1/users/me", headers={"Authorization": f"Bearer {second['accessToken']}"}).status_code == 200
    assert _refresh(client, second["refreshToken"]).status_code == 200


def test_replay_inside_the_window_does_not_touch_other_sessions(client, user):
    other = _login(client, user)
    _refresh(client, user.refresh)
    assert _refresh(client, user.refresh).status_code == 200
    assert _refresh(client, other["refreshToken"]).status_code == 200


def test_replay_after_the_window_revokes_every_session(client, db, user, settings):
    other = _login(client, user)
    new = _refresh(client, user.refresh).json()
    _age_revocation(db, user.refresh, settings.refresh_reuse_interval_seconds + 5)
    replay = _refresh(client, user.refresh)
    assert replay.status_code == 401
    assert replay.json()["code"] == "REFRESH_TOKEN_REUSED"
    assert _refresh(client, new["refreshToken"]).status_code == 401
    assert _refresh(client, other["refreshToken"]).status_code == 401


def test_a_token_revoked_by_purge_is_never_tolerated(client, db, user, settings):
    other = _login(client, user)
    # purge : un rejeu tardif révoque tout, y compris `other`
    new = _refresh(client, user.refresh).json()
    _age_revocation(db, user.refresh, settings.refresh_reuse_interval_seconds + 5)
    assert _refresh(client, user.refresh).status_code == 401
    # `new` et `other` sont désormais révoqués par purge (remplace_par NULL, révocation toute fraîche) : jamais tolérés
    for token in (new["refreshToken"], other["refreshToken"]):
        r = _refresh(client, token)
        assert r.status_code == 401
        assert r.json()["code"] == "REFRESH_TOKEN_REUSED"


def test_window_of_zero_disables_the_tolerance(client, user, settings, monkeypatch):
    monkeypatch.setattr(settings, "refresh_reuse_interval_seconds", 0)
    _refresh(client, user.refresh)
    r = _refresh(client, user.refresh)
    assert r.status_code == 401
    assert r.json()["code"] == "REFRESH_TOKEN_REUSED"


def test_successive_replays_follow_the_chain_to_the_active_token(client, user):
    _refresh(client, user.refresh)
    r1 = _refresh(client, user.refresh)  # rejeu 1 : remplace la paire du premier appel
    r2 = _refresh(client, user.refresh)  # rejeu 2 : remplace celle du rejeu 1
    assert r1.status_code == r2.status_code == 200
    assert _refresh(client, r1.json()["refreshToken"]).status_code == 200  # lui-même rejouable dans la fenêtre
    assert _refresh(client, r2.json()["refreshToken"]).status_code == 200


def test_expired_token_is_not_tolerated_even_inside_the_window(client, db, user):
    _refresh(client, user.refresh)
    db.execute(
        text(
            "UPDATE utilisateurs.jeton_rafraichissement "
            "SET cree_le = now() - interval '2 days', expire_le = now() - interval '1 day' WHERE empreinte = :d"
        ),
        {"d": _digest(user.refresh)},
    )
    db.commit()
    assert _refresh(client, user.refresh).json()["code"] == "REFRESH_TOKEN_REUSED"


def test_concurrent_refreshes_with_the_same_token_do_not_purge_the_account(client, user):
    other = _login(client, user)
    barrier = threading.Barrier(2)

    def call(_):
        barrier.wait()
        return _refresh(client, user.refresh)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(call, range(2)))
    assert [r.status_code for r in results] == [200, 200]
    # aucune purge : la dernière paire émise et l'autre session fonctionnent
    assert all(_refresh(client, r.json()["refreshToken"]).status_code == 200 for r in results)
    assert _refresh(client, other["refreshToken"]).status_code == 200


def test_remplace_par_requires_a_revocation(db, user):
    import pytest
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        db.execute(
            text(
                "UPDATE utilisateurs.jeton_rafraichissement SET remplace_par = id WHERE empreinte = :d"
            ),
            {"d": _digest(user.refresh)},
        )


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
