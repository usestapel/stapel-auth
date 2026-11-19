"""docs/schema.v2.json — this module's contract in profile 2 (stapel-tools codegen).

What a generated native client relies on, asserted on the committed artifact
(test_contract.py keeps it in sync with the source). Each fact is paired with
its inversion: the profile-1 docs/schema.json does not carry it, or the
neighbouring operation does not get it.
"""
import json
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parent.parent / "docs"
V1 = "/auth/api/v1"


@pytest.fixture(scope="module")
def v2():
    return json.loads((DOCS / "schema.v2.json").read_text())


@pytest.fixture(scope="module")
def v1():
    return json.loads((DOCS / "schema.json").read_text())


def _ops(schema):
    return [
        (method, path, op)
        for path, item in schema["paths"].items()
        for method, op in item.items()
        if isinstance(op, dict)
    ]


def test_profile_is_recorded(v2, v1):
    assert v2["info"]["x-stapel-contract"] == 2
    assert "x-stapel-contract" not in v1["info"]


def test_same_surface_as_profile1(v2, v1):
    assert {(m, p) for m, p, _ in _ops(v2)} == {(m, p) for m, p, _ in _ops(v1)}


def test_bearer_scheme_declared(v2, v1):
    assert v2["components"]["securitySchemes"]["JWTBearerAuth"]["scheme"] == "bearer"
    assert "JWTBearerAuth" not in v1["components"]["securitySchemes"]


@pytest.mark.parametrize("method,path", [
    ("post", "/email/request/"), ("post", "/email/verify/"),
    ("post", "/phone/request/"), ("post", "/phone/verify/"),
    ("post", "/anonymous/"), ("post", "/oauth/login/"),
    ("post", "/password/login/"), ("post", "/token/refresh/"),
])
def test_sign_in_operations_are_public(v2, method, path):
    assert {} in v2["paths"][V1 + path][method]["security"]


def test_inversion_profile1_marked_otp_sign_in_auth_required(v1):
    assert {} not in v1["paths"][V1 + "/email/verify/"]["post"]["security"]


@pytest.mark.parametrize("method,path", [
    ("get", "/me/"),                # gate admits, the handler answers 401 itself
    ("get", "/sessions/"),
    ("post", "/totp/disable/"),
])
def test_inversion_authenticated_operations_are_not_public(v2, method, path):
    assert {} not in v2["paths"][V1 + path][method]["security"]


def test_login_union_keyed_by_wire_status(v2, v1):
    mapping = v2["components"]["schemas"]["LoginResponse"]["discriminator"]["mapping"]
    assert mapping["LOGGED_IN"].endswith("/AuthResponse")
    assert mapping["TOTP_REQUIRED"].endswith("/TOTPChallengeResponse")
    assert mapping["FIRST_LOGIN_REQUIRED"].endswith("/FirstLoginChallengeResponse")
    assert "AuthResponse" in v1["components"]["schemas"]["LoginResponse"]["discriminator"]["mapping"]


def test_every_success_body_has_a_schema(v2):
    for method, path, op in _ops(v2):
        for status, response in op["responses"].items():
            if status.startswith("2") and status not in ("204", "205"):
                content = response.get("content") or {}
                assert content and all("schema" in m for m in content.values()), (
                    f"{method.upper()} {path} {status}"
                )


def test_session_minting_operations_declare_their_body(v2):
    challenge = v2["paths"][V1 + "/totp/challenge/verify/"]["post"]["responses"]["200"]
    assert challenge["content"]["application/json"]["schema"]["$ref"].endswith("/LoginResponse")
    passkey = v2["paths"][V1 + "/passkey/authenticate/complete/"]["post"]["responses"]["200"]
    assert passkey["content"]["application/json"]["schema"]["$ref"].endswith("/AuthResponse")


def test_email_verify_binds_the_codes_its_handler_returns(v2):
    responses = v2["paths"][V1 + "/email/verify/"]["post"]["responses"]
    assert "error.400.invalid_code_attempts" in responses["400"]["x-stapel-errors"]
    assert responses["423"]["x-stapel-errors"] == ["error.423.account_locked"]
    assert "error.503.verification_unavailable" in responses["503"]["x-stapel-errors"]


def test_bound_codes_are_registered_with_their_status(v2):
    registry = {e["code"]: e["status"] for e in json.loads((DOCS / "errors.json").read_text())}
    for method, path, op in _ops(v2):
        for status, response in op["responses"].items():
            for code in response.get("x-stapel-errors", []):
                assert registry.get(code) == int(status), f"{method} {path}: {code}"


def test_captcha_on_otp_request_only(v2):
    assert v2["paths"][V1 + "/email/request/"]["post"]["x-stapel-captcha"] == {
        "action": None, "token": {"field": "captcha_token"},
    }
    assert "x-stapel-captcha" not in v2["paths"][V1 + "/email/verify/"]["post"]


def test_flows_and_pagination_named(v2):
    assert "auth.passwordless_login" in v2["paths"][V1 + "/email/verify/"]["post"]["x-stapel-flows"]
    audit = v2["paths"][V1 + "/security/audit/"]["get"]["x-stapel-pagination"]
    assert audit == {"style": "page", "items": "results", "params": ["page"]}
