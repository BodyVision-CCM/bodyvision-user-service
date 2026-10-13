import uuid


def test_morphology_with_service_token(client, user, service_headers):
    client.patch(
        "/v1/users/me", headers=user.headers, json={"heightCm": 182, "weightKg": 78.25, "level": "ADVANCED"}
    )
    uid = client.get("/v1/users/me", headers=user.headers).json()["id"]
    r = client.get(f"/v1/internal/users/{uid}/morphology", headers=service_headers)
    assert r.status_code == 200
    assert r.json() == {"heightCm": 182, "weightKg": 78.25, "level": "ADVANCED"}


def test_morphology_of_a_user_without_data(client, user, service_headers):
    uid = client.get("/v1/users/me", headers=user.headers).json()["id"]
    r = client.get(f"/v1/internal/users/{uid}/morphology", headers=service_headers)
    assert r.json() == {"heightCm": None, "weightKg": None, "level": None}


def test_internal_endpoint_requires_the_service_token(client, user):
    uid = client.get("/v1/users/me", headers=user.headers).json()["id"]
    url = f"/v1/internal/users/{uid}/morphology"
    for headers in ({}, {"Authorization": "Bearer faux-jeton-de-service-000"}, user.headers):
        r = client.get(url, headers=headers)
        assert r.status_code == 401, headers
        assert r.json()["code"] == "INVALID_SERVICE_TOKEN"


def test_service_token_does_not_open_user_endpoints(client, service_headers):
    assert client.get("/v1/users/me", headers=service_headers).status_code == 401


def test_unknown_user_is_a_404(client, service_headers):
    r = client.get(f"/v1/internal/users/{uuid.uuid4()}/morphology", headers=service_headers)
    assert r.status_code == 404 and r.json()["code"] == "USER_NOT_FOUND"


def test_malformed_user_id_is_a_422(client, service_headers):
    assert client.get("/v1/internal/users/pas-un-uuid/morphology", headers=service_headers).status_code == 422
