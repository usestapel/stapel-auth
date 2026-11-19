"""The contract's examples and error params are facts a client can lean on.

1. Every example in the emitted contracts (``docs/schema.json``,
   ``docs/schema.v2.json``) validates against the schema it illustrates. A
   native client's suite found 16 of 72 that did not: an ``AuthResponse``
   example carrying only ``status``, a ``user`` with only ``id`` and
   ``email``, the string ``"True"`` for a boolean — and core's docstring
   reader drops every falsy example (``false``, ``[]``), so a field
   documented "Example: false" silently vanished from the object.
2. Every param an answer carries is listed in ``errors.json``: the wait
   params (``retry_after``, ``retry_after_display``, ``retry_after_minutes``)
   rode on 429/422/423 answers while the registry named only the minutes.

The bodies the server really sends are validated against the same schemas by
``test_contract_wire.py`` (every declared operation, password sign-in
included), so the examples were completed to the schema, not the schema
loosened to the examples. The 429 wire answer: ``test_rate_limit_contract.py``.
"""
import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

DOCS = Path(__file__).resolve().parent.parent / "docs"

#: Examples this module emits but does not own, with the owner who must fix
#: them. The gate fails when one of them starts validating (stale entry).
FOREIGN = {
    # stapel-gdpr's DataOwnerHealthDTO: `alive: false` is dropped by core's
    # docstring reader (falsy example), so its example lacks a required field.
    ("get", "/auth/api/v1/owners/health", "200", "DataOwnerHealthDTO"): "stapel-gdpr",
}


def _openapi30_to_jsonschema(node):
    """``nullable: true`` is OpenAPI 3.0; JSON Schema spells it as a null branch."""
    if isinstance(node, list):
        return [_openapi30_to_jsonschema(n) for n in node]
    if not isinstance(node, dict):
        return node
    out = {k: _openapi30_to_jsonschema(v) for k, v in node.items() if k != "nullable"}
    if node.get("nullable"):
        return {"anyOf": [out, {"type": "null"}]}
    return out


def _examples(schema):
    for path, item in schema["paths"].items():
        for method, op in item.items():
            if not isinstance(op, dict):
                continue
            medias = [("request", m) for m in ((op.get("requestBody") or {}).get("content") or {}).values()]
            for status, response in (op.get("responses") or {}).items():
                medias += [(status, m) for m in (response.get("content") or {}).values()]
            for where, media in medias:
                if "schema" not in media:
                    continue
                if "example" in media:
                    yield (method, path, where, "example"), media["schema"], media["example"]
                for name, ex in (media.get("examples") or {}).items():
                    if "value" in ex:
                        yield (method, path, where, name), media["schema"], ex["value"]


def invalid_examples(schema):
    """``{(method, path, status, name): [error, ...]}`` and the count checked."""
    components = _openapi30_to_jsonschema(copy.deepcopy(schema.get("components") or {}))
    bad, checked = {}, 0
    for key, media_schema, value in _examples(schema):
        checked += 1
        root = {**_openapi30_to_jsonschema(media_schema), "components": components}
        errors = [f"{list(e.absolute_path)}: {e.message[:160]}" for e in Draft202012Validator(root).iter_errors(value)]
        if errors:
            bad[key] = errors
    return bad, checked


@pytest.mark.parametrize("artifact", ["schema.json", "schema.v2.json"])
def test_every_example_validates_against_its_schema(artifact):
    bad, checked = invalid_examples(json.loads((DOCS / artifact).read_text()))
    assert checked >= 70, f"checked {checked} examples — the walk lost the subject"
    own = {k: v for k, v in bad.items() if k not in FOREIGN}
    assert own == {}, json.dumps({" ".join(k): v for k, v in own.items()}, indent=1)
    stale = [k for k in FOREIGN if k not in bad]
    assert stale == [], f"FOREIGN entries that now validate — remove them: {stale}"


def test_inversion_a_partial_example_is_caught():
    schema = json.loads((DOCS / "schema.v2.json").read_text())
    media = schema["paths"]["/auth/api/v1/sessions/"]["get"]["responses"]["200"]["content"]["application/json"]
    example = next(iter(media["examples"].values()))
    del example["value"][0]["is_suspicious"]
    bad, _ = invalid_examples(schema)
    assert any(k[1] == "/auth/api/v1/sessions/" for k in bad)


def test_inversion_a_string_for_a_boolean_is_caught():
    schema = json.loads((DOCS / "schema.v2.json").read_text())
    media = schema["paths"]["/auth/api/v1/verification/{challenge_id}/complete/"]["post"]["responses"]["200"]["content"]["application/json"]
    next(iter(media["examples"].values()))["value"]["verified"] = "True"
    bad, _ = invalid_examples(schema)
    assert any(k[1].endswith("/complete/") for k in bad)


# --- error params ----------------------------------------------------------


def _errors():
    return {e["code"]: e for e in json.loads((DOCS / "errors.json").read_text())}


@pytest.mark.parametrize("code", ["error.429.rate_limit", "error.422.blocked", "error.423.account_locked"])
def test_wait_answers_document_every_param_they_carry(code):
    from stapel_core.django.api.errors import error_429_rate_limit

    from stapel_auth.errors import RETRY_PARAMS, retry_params

    assert set(retry_params(30)) == set(RETRY_PARAMS)
    assert set(error_429_rate_limit(30).data["params"]) == set(RETRY_PARAMS)
    assert set(RETRY_PARAMS) <= set(_errors()[code]["params"]), _errors()[code]


def test_minutes_round_up():
    from stapel_auth.errors import retry_params

    assert retry_params(30) == {"retry_after": 30, "retry_after_minutes": 1, "retry_after_display": "0:30"}
    assert retry_params(61)["retry_after_minutes"] == 2

