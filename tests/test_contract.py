"""Conformité du service au contrat OpenAPI (approche API-First : le contrat fait foi).

Le contrat vit dans le dépôt `bodyvision-contracts` ; une copie (instantané) est dans `contracts/openapi.yaml`
à la racine de CE dépôt, pour que les tests tournent seuls, y compris en CI. À resynchroniser quand le contrat
change. Pour tester contre la source : CONTRACT_PATH=../bodyvision-contracts/openapi.yaml pytest
Le test ne couvre que les routes de CE service (tags auth, users, internal).
"""

import os
from pathlib import Path

import pytest
import yaml

CONTRACT = Path(os.environ.get("CONTRACT_PATH", Path(__file__).resolve().parents[1] / "contracts" / "openapi.yaml"))
MY_TAGS = {"auth", "users", "internal"}
PREFIX = "/v1"  # le contrat déclare le serveur en /v1 ; ce service inclut le préfixe dans ses routes

pytestmark = pytest.mark.skipif(not CONTRACT.exists(), reason=f"contrat introuvable ({CONTRACT})")


@pytest.fixture(scope="module")
def contract():
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def spec(app):
    return app.openapi()


def resolve(doc, node):
    """Déroule $ref et allOf d'un schéma du contrat."""
    if "$ref" in node:
        return resolve(doc, doc["components"]["schemas"][node["$ref"].rsplit("/", 1)[1]])
    if "allOf" in node:
        merged = {"properties": {}, "required": []}
        for part in node["allOf"]:
            p = resolve(doc, part)
            merged["properties"].update(p.get("properties", {}))
            merged["required"] += p.get("required", [])
        return merged
    return node


def my_operations(contract):
    for path, item in contract["paths"].items():
        for method, op in item.items():
            if method in {"get", "post", "put", "patch", "delete"} and set(op.get("tags", [])) & MY_TAGS:
                yield path, method, op


def test_every_contract_route_of_this_service_exists_with_its_status_codes(contract, spec):
    checked = 0
    for path, method, op in my_operations(contract):
        app_path = PREFIX + path
        assert app_path in spec["paths"], f"{method.upper()} {path} est dans le contrat mais pas dans le service"
        app_op = spec["paths"][app_path].get(method)
        assert app_op is not None, f"{method.upper()} {app_path} manque"
        missing = set(op["responses"]) - set(app_op["responses"])
        assert not missing, f"{method.upper()} {app_path} : codes du contrat non documentés par le service : {missing}"
        checked += 1
    assert checked == 6, "le contrat doit exposer 6 opérations pour ce service (3 auth, 2 users, 1 internal)"


def test_security_requirements_match(contract, spec):
    for path, method, op in my_operations(contract):
        contract_secured = op.get("security", contract.get("security", [])) != []
        app_op = spec["paths"][PREFIX + path][method]
        assert bool(app_op.get("security")) == contract_secured, f"{method.upper()} {path} : sécurité différente"
        if "security" in op and op["security"]:
            assert set(op["security"][0]) <= {k for s in app_op["security"] for k in s}, f"{method.upper()} {path}"


@pytest.mark.parametrize("name", ["Credentials", "TokenPair", "Morphology", "UserProfile"])
def test_schema_fields_match_the_contract(contract, spec, name):
    expected = resolve(contract, {"$ref": f"#/components/schemas/{name}"})
    actual = spec["components"]["schemas"][name]
    assert set(actual["properties"]) == set(expected["properties"]), f"champs de {name} différents du contrat"
    assert set(expected.get("required", [])) <= set(actual.get("required", [])), f"{name} : champs requis du contrat"
    for field, definition in expected["properties"].items():
        if "enum" in definition:
            got = actual["properties"][field]
            got_enum = got.get("enum") or next(x["enum"] for x in got.get("anyOf", []) if "enum" in x)
            assert set(got_enum) == set(definition["enum"]), f"{name}.{field} : valeurs différentes"


def test_nested_settings_match_the_contract(contract, spec):
    expected = resolve(contract, {"$ref": "#/components/schemas/UserProfile"})["properties"]["settings"]
    actual = spec["components"]["schemas"]["UserSettings"]
    assert set(actual["properties"]) == set(expected["properties"])
    assert set(actual["properties"]["uploadMode"]["enum"]) == set(expected["properties"]["uploadMode"]["enum"])


def test_patch_body_only_accepts_fields_the_contract_defines(contract, spec):
    allowed = set(resolve(contract, {"$ref": "#/components/schemas/UserProfile"})["properties"])
    assert set(spec["components"]["schemas"]["UserProfileUpdate"]["properties"]) <= allowed


def test_password_rule_matches_the_contract(contract, spec):
    expected = resolve(contract, {"$ref": "#/components/schemas/Credentials"})["properties"]["password"]
    actual = spec["components"]["schemas"]["Credentials"]["properties"]["password"]
    assert actual["minLength"] == expected["minLength"] == 10


def test_error_schema_matches_the_contract(contract, spec):
    expected = resolve(contract, {"$ref": "#/components/schemas/Error"})
    actual = spec["components"]["schemas"]["Error"]
    assert set(actual["properties"]) == set(expected["properties"])
    assert set(expected["required"]) <= set(actual["required"])
