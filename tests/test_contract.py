"""Conformité du service au contrat OpenAPI (approche API-First : le contrat fait foi).

Le contrat vit dans le dépôt `bodyvision-contracts` ; une copie (instantané) est dans `contracts/openapi.yaml`
à la racine de CE dépôt, pour que les tests tournent seuls, y compris en CI. À resynchroniser quand le contrat
change. Pour tester contre la source : CONTRACT_PATH=../bodyvision-contracts/openapi.yaml pytest
Le test couvre les routes de CE service (tags auth, users, internal, ops) : API versionnée /v1, mais aussi
sondes et JWKS, que le contrat place hors /v1 via un `servers` propre au chemin.
"""

import os
from pathlib import Path

import pytest
import yaml

CONTRACT = Path(os.environ.get("CONTRACT_PATH", Path(__file__).resolve().parents[1] / "contracts" / "openapi.yaml"))
MY_TAGS = {"auth", "users", "internal", "ops"}
PREFIX = "/v1"  # le contrat déclare le serveur en /v1 ; ce service inclut le préfixe dans ses routes
EXPECTED_OPERATIONS = 9  # 3 auth + JWKS, 2 users, 1 internal, 2 sondes

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
                yield path, method, op, app_path(item, op, path)


def app_path(item, op, path):
    """Chemin réel dans le service : la racine si le contrat surcharge `servers` pour ce chemin ou cette opération
    (sondes, JWKS), sinon sous /v1."""
    return path if ("servers" in item or "servers" in op) else PREFIX + path


def test_every_contract_route_of_this_service_exists_with_its_status_codes(contract, spec):
    checked = 0
    for path, method, op, app_path in my_operations(contract):
        assert app_path in spec["paths"], f"{method.upper()} {path} est dans le contrat mais pas dans le service"
        app_op = spec["paths"][app_path].get(method)
        assert app_op is not None, f"{method.upper()} {app_path} manque"
        # Dans les DEUX sens : un code que le service renvoie doit être au contrat (un client généré ne
        # connaît que le contrat), et un code du contrat que le service ne renvoie jamais est une promesse en l'air.
        assert set(op["responses"]) == set(app_op["responses"]), (
            f"{method.upper()} {app_path} : codes de statut différents. Contrat : {sorted(op['responses'])}, "
            f"service : {sorted(app_op['responses'])}"
        )
        checked += 1
    assert checked == EXPECTED_OPERATIONS, "le contrat doit exposer 9 opérations pour ce service"


def test_security_requirements_match(contract, spec):
    for path, method, op, app_path in my_operations(contract):
        contract_secured = op.get("security", contract.get("security", [])) != []
        app_op = spec["paths"][app_path][method]
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
            assert set(got_enum) - {None} == set(definition["enum"]) - {None}, f"{name}.{field} : valeurs différentes"


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


def test_operation_ids_match_the_contract(contract, spec):
    """L'operationId nomme la fonction générée (oapi-codegen, openapi-python-client...) : Go et Python doivent
    parler le même vocabulaire. Comparé opération par opération, sondes et JWKS compris."""
    checked = 0
    for path, method, op, app_path in my_operations(contract):
        got = spec["paths"][app_path][method].get("operationId")
        assert got == op["operationId"], (
            f"{method.upper()} {path} : operationId {got!r} dans le service, {op['operationId']!r} dans le contrat"
        )
        checked += 1
    assert checked == EXPECTED_OPERATIONS


def test_probes_and_jwks_are_declared_outside_v1(contract):
    for path in ("/healthz", "/readyz", "/.well-known/jwks.json"):
        item = contract["paths"][path]
        servers = item.get("servers") or item["get"].get("servers")
        assert servers, f"{path} doit déclarer son propre `servers` (hors /v1)"
        assert all(not srv["url"].rstrip("/").endswith("/v1") for srv in servers)
    assert contract["paths"]["/.well-known/jwks.json"]["get"]["security"] == []


def jwk_schema_of(contract):
    """Schéma d'une clé, déduit de la réponse 200 du JWKS (quel que soit le nom des schémas du contrat)."""
    response = contract["paths"]["/.well-known/jwks.json"]["get"]["responses"]["200"]
    keys = resolve(contract, response["content"]["application/json"]["schema"])["properties"]["keys"]
    return resolve(contract, keys["items"])


def test_jwks_response_matches_the_contract_schema(contract, client):
    r = client.get("/.well-known/jwks.json")
    assert r.status_code == 200
    jwk_schema = jwk_schema_of(contract)
    keys = r.json()["keys"]
    assert keys, "au moins une clé publiée"
    for key in keys:
        assert set(jwk_schema.get("required", [])) <= set(key), "champs requis du contrat absents de la clé"
        assert set(key) <= set(jwk_schema["properties"]), "champ non prévu par le contrat"
    assert "max-age" in r.headers["cache-control"]


# --- Comparaison structurelle, dans les deux sens : corps de requête, corps de réponse, paramètres ----------------
# Ce qui compte pour un client généré : type, format, valeurs permises, bornes, champs requis, nullabilité.
# Les descriptions, exemples et valeurs par défaut ne sont pas comparés.

CONSTRAINTS = ("type", "format", "minLength", "maxLength", "minimum", "maximum", "pattern", "minItems", "maxItems")


def deref(doc, node):
    while isinstance(node, dict) and "$ref" in node:
        target = doc
        for part in node["$ref"].lstrip("#/").split("/"):
            target = target[part]
        node = target
    return node


def normalize(doc, node):
    node = deref(doc, node)
    if "allOf" in node:
        merged = {"type": "object", "nullable": False, "properties": {}, "required": []}
        for part in node["allOf"]:
            p = normalize(doc, part)
            merged["properties"].update(p.get("properties", {}))
            merged["required"] += p.get("required", [])
        return merged
    if "anyOf" in node:  # Pydantic écrit « X | None » ainsi
        non_null = [x for x in node["anyOf"] if x.get("type") != "null"]
        assert len(non_null) == 1, f"anyOf non géré : {node}"
        return {**normalize(doc, non_null[0]), "nullable": True}
    result = {k: node[k] for k in CONSTRAINTS if k in node}
    if "enum" in node:
        result["enum"] = {v for v in node["enum"] if v is not None}
    if "const" in node:
        result["enum"] = {node["const"]}
    result["nullable"] = bool(node.get("nullable")) or (None in node.get("enum", []))
    for key in ("properties", "items"):
        if key in node:
            result[key] = node[key]
    if "properties" in node:
        result["required"] = list(node.get("required", []))
    return result


def schema_differences(path, contract_doc, contract_node, app_doc, app_node):
    a, b = normalize(contract_doc, contract_node), normalize(app_doc, app_node)
    diffs = []
    for key in (*CONSTRAINTS, "enum", "nullable"):
        if a.get(key) != b.get(key):
            diffs.append(f"{path} : {key} = {a.get(key)!r} au contrat, {b.get(key)!r} dans le service")
    if "properties" in a or "properties" in b:
        pa, pb = a.get("properties", {}), b.get("properties", {})
        for name in sorted(set(pa) | set(pb)):
            if name not in pa:
                diffs.append(f"{path}.{name} : champ du service absent du contrat")
            elif name not in pb:
                diffs.append(f"{path}.{name} : champ du contrat absent du service")
            else:
                diffs += schema_differences(f"{path}.{name}", contract_doc, pa[name], app_doc, pb[name])
        if set(a.get("required", [])) != set(b.get("required", [])):
            diffs.append(
                f"{path} : champs requis {sorted(a.get('required', []))} au contrat, {sorted(b.get('required', []))} "
                "dans le service"
            )
    if "items" in a and "items" in b:
        diffs += schema_differences(path + "[]", contract_doc, a["items"], app_doc, b["items"])
    return diffs


def json_schema(doc, container):
    container = deref(doc, container)
    media = container.get("content", {}).get("application/json")
    return media["schema"] if media else None


def test_request_and_response_bodies_are_identical_to_the_contract(contract, spec):
    diffs, compared = [], 0
    for path, method, op, app_path in my_operations(contract):
        app_op = spec["paths"][app_path][method]
        label = f"{method.upper()} {path}"
        c_body, a_body = json_schema(contract, op.get("requestBody", {})), json_schema(spec, app_op.get("requestBody", {}))
        assert bool(c_body) == bool(a_body), f"{label} : corps de requête présent d'un seul côté"
        if c_body:
            assert op["requestBody"].get("required", False) == app_op["requestBody"].get("required", False), (
                f"{label} : corps de requête obligatoire d'un seul côté"
            )
            diffs += schema_differences(f"{label} [corps]", contract, c_body, spec, a_body)
            compared += 1
        for code, response in op["responses"].items():
            c_schema, a_schema = json_schema(contract, response), json_schema(spec, app_op["responses"][code])
            assert bool(c_schema) == bool(a_schema), f"{label} [{code}] : corps de réponse présent d'un seul côté"
            if c_schema:
                diffs += schema_differences(f"{label} [{code}]", contract, c_schema, spec, a_schema)
                compared += 1
    assert not diffs, "écarts entre le contrat et le service :\n  " + "\n  ".join(diffs)
    assert compared >= 20, "la comparaison doit couvrir toutes les requêtes et réponses JSON"


def test_parameters_and_headers_are_identical_to_the_contract(contract, spec):
    for path, method, op, app_path in my_operations(contract):
        app_op = spec["paths"][app_path][method]

        def params(doc, operation, item=None):
            found = list(operation.get("parameters", [])) + list((item or {}).get("parameters", []))
            return {(p["name"], p["in"], bool(p.get("required"))) for p in (deref(doc, x) for x in found)}

        assert params(contract, op, contract["paths"][path]) == params(spec, app_op), f"{method.upper()} {path} : paramètres"
    # En-tête documenté des deux côtés (cache de la clé publique)
    c_headers = contract["paths"]["/.well-known/jwks.json"]["get"]["responses"]["200"]["headers"]
    a_headers = spec["paths"]["/.well-known/jwks.json"]["get"]["responses"]["200"]["headers"]
    assert set(c_headers) == set(a_headers) == {"Cache-Control"}
