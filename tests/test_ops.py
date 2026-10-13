import jwt
from fastapi.testclient import TestClient
from sqlalchemy import create_engine


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_readyz_is_up_when_the_database_answers(client):
    r = client.get("/readyz")
    assert r.status_code == 200 and r.json()["database"] == "up"


def test_readyz_is_503_when_the_database_is_down(client, monkeypatch):
    dead = create_engine("postgresql+psycopg://x:y@127.0.0.1:1/z", connect_args={"connect_timeout": 1})
    monkeypatch.setattr("app.routers.ops.get_engine", lambda: dead)
    r = client.get("/readyz")
    assert r.status_code == 503 and r.json()["database"] == "down"
    assert client.get("/healthz").status_code == 200, "healthz ne dépend pas de la base"


def test_jwks_publishes_a_key_that_verifies_issued_tokens(client, settings, user):
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    assert "max-age" in r.headers["cache-control"]
    (jwk,) = r.json()["keys"]
    assert jwk["kty"] == "RSA" and jwk["alg"] == "RS256" and jwk["use"] == "sig"
    assert "d" not in jwk and "p" not in jwk, "la clé privée ne doit jamais être publiée"

    # ce que fera un autre service : lire le kid, prendre la clé publique, valider le jeton localement
    assert jwt.get_unverified_header(user.access)["kid"] == jwk["kid"]
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    claims = jwt.decode(user.access, public_key, algorithms=["RS256"], audience=settings.jwt_audience)
    assert claims["iss"] == settings.jwt_issuer and claims["exp"] - claims["iat"] == settings.access_token_ttl_seconds


def test_metrics_endpoint(client):
    client.get("/healthz")
    r = client.get("/metrics")
    assert r.status_code == 200 and "http_request" in r.text


def test_swagger_and_openapi_are_served(client):
    assert "swagger-ui" in client.get("/docs").text.lower()
    assert client.get("/redoc").status_code == 200
    spec = client.get("/openapi.json").json()
    assert spec["info"]["title"] == "BodyVision – Service Auth"
    assert set(spec["components"]["securitySchemes"]) == {"bearerAuth", "serviceToken"}
    assert "/v1/auth/login" in spec["paths"]
    assert "HTTPValidationError" not in spec["components"]["schemas"], "les 422 documentés sont au format Error"


def test_every_response_carries_a_request_id_that_matches_error_bodies(client):
    ok = client.get("/healthz")
    assert len(ok.headers["x-request-id"]) >= 8
    err = client.get("/v1/users/me")
    assert err.json()["traceId"] == err.headers["x-request-id"]


def test_a_valid_incoming_request_id_is_reused_and_an_unsafe_one_is_replaced(client):
    r = client.get("/v1/users/me", headers={"X-Request-ID": "mobile-req-12345"})
    assert r.headers["x-request-id"] == "mobile-req-12345" and r.json()["traceId"] == "mobile-req-12345"
    bad = client.get("/healthz", headers={"X-Request-ID": "x\ninjection"})
    assert bad.headers["x-request-id"] != "x\ninjection"


def test_unknown_route_and_wrong_method_use_the_error_format(client):
    r = client.get("/v1/nexiste-pas")
    assert r.status_code == 404 and r.json()["code"] == "NOT_FOUND"
    r = client.get("/v1/auth/login")
    assert r.status_code == 405 and r.json()["code"] == "METHOD_NOT_ALLOWED"


def test_unhandled_exception_is_a_500_without_leaking_details(app):
    @app.get("/__boom", include_in_schema=False)
    def boom():
        raise RuntimeError("secret interne : mot-de-passe-db")

    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            r = c.get("/__boom")
    finally:
        app.router.routes[:] = [x for x in app.router.routes if getattr(x, "path", "") != "/__boom"]
    assert r.status_code == 500
    assert r.json()["code"] == "INTERNAL_ERROR" and r.json()["traceId"]
    assert "secret" not in r.text and "Traceback" not in r.text
