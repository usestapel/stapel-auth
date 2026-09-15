"""Every response body the contract declares is a body the views actually send.

``docs/schema.json`` is emitted from the views' ``@extend_schema`` annotations,
and an annotation is a CLAIM: it says what the view returns, and the generator
has no way to check it against the method body. ``tests/test_contract.py``
compares the committed document against a FRESH EMISSION of the same
annotations — it proves the file is not stale, and nothing else, because both
sides come from the claim. stapel-alerts 0.2.0 shipped ``GET /issues``
declared as ``Issue[]`` while the wire carried ``{count, offset, limit,
results}``: the drift gate was green and the frontend pair rendered
``undefined``.

This is the gate the generator cannot be: it performs every operation the
committed schema declares with a JSON response body, and validates the body it
gets against the schema it was promised.

Rules this file holds itself to:

* an operation with a declared JSON response and no entry in ``RECIPES``
  FAILS LOUDLY — a gate that quietly covers three of four rows is the family
  of green that proves nothing;
* a path parameter the gate cannot fill fails at the point of substitution,
  naming the operation;
* the operations that genuinely cannot be driven in-process are listed by
  name in ``UNDRIVABLE`` with a one-line reason each. That list is asserted
  to be exactly current: a stale entry, or a missing reason, fails.

Runs on every interpreter: it reads the committed schema and never emits.

The urlconf below is the emission mount (``codegen_urls.py``): auth AND gdpr
under ``auth/api/``. ``tests/conftest_urls.py`` mounts auth alone, so the
gdpr half of auth's own contract is unreachable under it.

What it found on its first run (96 of 97 operations driven, 2 red):

* ``POST /oauth2/introspect/`` declares ``exp`` and ``iat`` as integers and
  answers ``null`` for both on every ACTIVE token. The claims are real in the
  JWT; ``JWTHandler.extract_user_data`` strips ``exp``/``iat``/``jti``/
  ``token_type`` before the view reads them, so ``payload.get("exp")`` can
  never be anything else. An RFC 7662 consumer gets a null where the contract
  promises a unix timestamp.
* ``GET /security/status/`` declares ``totp.backup_codes_remaining`` as a
  REQUIRED integer and answers ``null`` for every account without TOTP —
  ``TOTPService.backup_codes_remaining`` is typed ``int | None`` and returns
  None when there is no active device, while the DTO field is annotated
  ``int``, which is what the emitter copied.

Both are left exactly as they are: this is a gate, not a fix.
"""
import copy
import json
import uuid
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

import jsonschema
import pytest
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import include, path as url_path
from django.utils import timezone
from rest_framework.test import APIClient

from stapel_core.django.jwt.provider import jwt_provider

REPO = Path(__file__).resolve().parent.parent
SCHEMA = json.loads((REPO / "docs" / "schema.json").read_text())

#: The mount the contract is emitted at, reproduced for the test client.
urlpatterns = [
    url_path("auth/api/", include("stapel_auth.urls")),
    url_path("auth/api/", include("stapel_gdpr.urls")),
]

pytestmark = [pytest.mark.django_db, pytest.mark.urls(__name__)]

V1 = "/auth/api/v1"
PASSWORD = "wire-contract-password-7"
OTP_CODE = "0000"  # MOCK_OTP_CODE in the harness settings


@pytest.fixture(autouse=True)
def _media_root(tmp_path):
    """Keep the export machinery's files out of the checkout.

    ``MEDIA_ROOT`` is unset in the harness settings, so it defaults to the
    working directory and the data-export run writes ``gdpr/exports/*.zip``
    into the repo root — where, under this package's flat layout, a ``gdpr/``
    directory also shadows ``stapel_auth.gdpr``.
    """
    with override_settings(MEDIA_ROOT=str(tmp_path)):
        yield


# ─────────────────────────────────────────────────────────────────────────────
# The contract side: what the document declares
# ─────────────────────────────────────────────────────────────────────────────


def _blank_string_alternative(node):
    """A ``oneOf`` branch that means "or the empty string".

    ``URLField(allow_blank=True)`` is emitted as ``oneOf: [{format: uri,
    maxLength: 500}, {maxLength: 0}]``. The two branches are disjoint only
    under format-ASSERTING semantics; JSON Schema treats ``format`` as an
    annotation, so ``""`` matches both and the exclusive ``oneOf`` fails on a
    value the document plainly allows. That is a validator-semantics gap, not
    a claim the wire breaks — so the branches are read as alternatives.
    """
    branches = node.get("oneOf")
    if not isinstance(branches, list):
        return False
    return any(
        isinstance(b, dict) and b.get("type") == "string" and b.get("maxLength") == 0
        for b in branches
    )


def _json_schema(node):
    """OpenAPI 3.0 → JSON Schema, for the divergences that matter here.

    OAS 3.0 spells "may be null" as ``nullable: true`` beside a ``type``;
    JSON Schema has no such keyword and would refuse the null. The second
    conversion is the blank-string ``oneOf`` above. Everything else
    drf-spectacular emits (``$ref``, ``allOf``, ``enum``, ``required``,
    ``readOnly``) is JSON Schema as written.
    """
    if isinstance(node, list):
        return [_json_schema(item) for item in node]
    if not isinstance(node, dict):
        return node
    rebuilt = {k: _json_schema(v) for k, v in node.items() if k != "nullable"}
    if _blank_string_alternative(rebuilt):
        rebuilt["anyOf"] = rebuilt.pop("oneOf")
    if node.get("nullable"):
        return {"anyOf": [rebuilt, {"type": "null"}]}
    return rebuilt


def _validator(response_schema):
    root = copy.deepcopy(response_schema)
    root["components"] = copy.deepcopy(SCHEMA["components"])
    return jsonschema.Draft202012Validator(_json_schema(root))


def _operations():
    """Every ``(method, path, 2xx code, JSON body schema)`` the contract declares."""
    ops = []
    for path, methods in SCHEMA["paths"].items():
        for method, op in methods.items():
            if method not in {"get", "post", "put", "patch", "delete"}:
                continue
            for code, response in op.get("responses", {}).items():
                body = (
                    response.get("content", {})
                    .get("application/json", {})
                    .get("schema")
                )
                if body is not None and code.startswith("2"):
                    ops.append((method.upper(), path, int(code), body))
    return sorted(ops, key=lambda o: (o[1], o[0]))


OPERATIONS = _operations()


# ─────────────────────────────────────────────────────────────────────────────
# The wire side: harness
# ─────────────────────────────────────────────────────────────────────────────


def _unique(prefix):
    return f"{prefix}{uuid.uuid4().hex[:10]}"


def make_user(**kwargs):
    User = get_user_model()
    defaults = dict(
        email=f"{_unique('wire-')}@example.com",
        username=_unique("wire_"),
        password=PASSWORD,
        is_email_verified=True,
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


def make_staff(**kwargs):
    kwargs.setdefault("is_staff", True)
    kwargs.setdefault("is_superuser", True)
    return make_user(**kwargs)


def client_for(user=None, **extra):
    """An APIClient, bearing ``user``'s access token when one is given."""
    client = APIClient(**extra)
    if user is not None:
        access, _ = jwt_provider.create_tokens(user)
        client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return client


def anonymous():
    return APIClient()


def service_key():
    from stapel_auth.models import ServiceAPIKey

    return ServiceAPIKey.objects.create(
        name=_unique("wire-svc-"), key=_unique("svc-"), is_active=True
    ).key


def password_on(**extra):
    """The password doors are off by default (conf.py) — the views 403 without this."""
    flags = {"AUTH_PASSWORD_LOGIN": True, "AUTH_PASSWORD_REGISTRATION": True}
    flags.update(extra)
    return override_settings(STAPEL_AUTH=flags)


def gdpr_settings():
    """A fresh override each time: one instance cannot be entered twice."""
    return override_settings(
        STAPEL_GDPR={
            "DATA_OWNERS": ["auth"],
            "DATA_OWNERS_VERSION": "wire-contract-1",
            "SUBJECT_TYPES": ["account"],
            "GRACE_PERIOD_DAYS": 30,
        }
    )


def otp_login(email=None):
    """Email OTP round trip — the cheapest way to a real tracked session."""
    client = anonymous()
    email = email or f"{_unique('wire-')}@example.com"
    assert client.post(f"{V1}/email/request/", {"email": email}).status_code == 200
    response = client.post(
        f"{V1}/email/verify/", {"email": email, "code": OTP_CODE}, format="json"
    )
    assert response.status_code == 200, response.content
    return response.json()


def make_session(user, **kwargs):
    from stapel_auth.models import UserSession

    defaults = dict(
        jti=uuid.uuid4().hex,
        device_name="Chrome on Mac",
        device_type="desktop",
        expires_at=timezone.now() + timedelta(days=30),
    )
    defaults.update(kwargs)
    return UserSession.objects.create(user=user, **defaults)


def make_audit_entry(user):
    from stapel_auth.models import AuthAuditLog

    return AuthAuditLog.objects.create(
        user=user,
        event_type="login_success",
        ip_address="1.1.1.1",
        user_agent="wire-contract",
        metadata={},
    )


def make_passkey(user, **kwargs):
    from stapel_auth.models import PasskeyCredential

    defaults = dict(
        credential_id=uuid.uuid4().bytes,
        public_key=b"wire-contract-public-key",
        device_name="Wire key",
        transports=["internal"],
    )
    defaults.update(kwargs)
    return PasskeyCredential.objects.create(user=user, **defaults)


def make_org(slug=None, **kwargs):
    from stapel_auth.models import Organization

    slug = slug or _unique("org")
    defaults = dict(name="Wire Org", slug=slug, domain=f"{slug}.example.com")
    defaults.update(kwargs)
    return Organization.objects.create(**defaults)


def enable_totp(user):
    """Real enrollment through the real service — returns the shared secret."""
    import pyotp

    from stapel_auth.mfa.services import TOTPService

    secret = TOTPService.setup(user)["secret"]
    TOTPService.confirm(user, pyotp.TOTP(secret, digits=TOTPService.CODE_LENGTH).now())
    return secret


def instant_change_token(client, kind):
    """Steps 1-2 of an instant authenticator change: the proven-old change token."""
    assert client.post(f"{V1}/{kind}/change/instant/request-old/", {}).status_code == 200
    response = client.post(
        f"{V1}/{kind}/change/instant/verify-old/", {"code": OTP_CODE}, format="json"
    )
    assert response.status_code == 200, response.content
    return response.json()["change_token"]


def first_login_challenge(user, expected):
    """A password login that stops at a first-login intermediate (org-program §C2)."""
    response = anonymous().post(
        f"{V1}/password/login/",
        {"login": user.username, "password": PASSWORD},
        format="json",
    )
    assert response.status_code == 200, response.content
    body = response.json()
    assert body.get("requires") == expected, body
    return body["challenge_token"]


def provisioned_user(**flags):
    """Org-provisioned account: namespaced username, no email anchor."""
    User = get_user_model()
    user = User.objects.create(
        username=f"{_unique('org')}/{_unique('u')}", email=None, auth_type="login", **flags
    )
    user.set_password(PASSWORD)
    user.save(update_fields=["password"])
    return user


def qr_key(client=None, qr_type="login_request"):
    """A QR key, generated by ``client`` — the key is bound to that device."""
    client = client or anonymous()
    response = client.post(f"{V1}/qr/generate/", {"type": qr_type}, format="json")
    assert response.status_code == 201, response.content
    return response.json()["key"]


def challenge_for(user, scope="wire_contract", factors=("otp_email",)):
    from stapel_core.verification import create_challenge

    return create_challenge(user, scope, list(factors), 300)["challenge_id"]


def dsar_row(kind="access"):
    response = anonymous().post(
        f"{V1}/dsar", {"kind": kind, "email": f"{_unique('dsar-')}@example.com"},
        format="json",
    )
    assert response.status_code == 201, response.content
    return response.json()["request_id"]


def closed_account():
    """Close an account and hand back the single-purpose closure token."""
    user = make_user()
    with gdpr_settings():
        response = client_for(user).post(f"{V1}/user/account/close", {}, format="json")
    assert response.status_code == 202, response.content
    return response.json()["closure_token"]


# ─────────────────────────────────────────────────────────────────────────────
# The recipe table
# ─────────────────────────────────────────────────────────────────────────────


class Call:
    """Performs one declared operation, and refuses to guess a path parameter."""

    def __init__(self, method, path):
        self.method = method
        self.path = path

    def __call__(self, client, params=None, data=None, query="", **extra):
        url = self.path
        for name, value in (params or {}).items():
            url = url.replace("{%s}" % name, str(value))
        assert "{" not in url, (
            f"{self.method} {self.path}: a path parameter this gate does not "
            "know how to fill — teach its recipe, or the operation goes unchecked"
        )
        send = getattr(client, self.method.lower())
        if self.method in ("GET", "DELETE"):
            return send(url + query, **extra)
        return send(url + query, data if data is not None else {}, format="json", **extra)


#: How to perform each operation the contract declares with a JSON response
#: body, keyed by ``(METHOD, path template)``. Each recipe receives a ``Call``
#: bound to that operation and returns the response it produced.
RECIPES = {}


def recipe(method, path):
    def register(fn):
        key = (method, V1 + path)
        assert key not in RECIPES, f"duplicate recipe for {method} {path}"
        RECIPES[key] = fn
        return fn

    return register


#: Operations that cannot be driven in-process, by name and with the reason.
#: A short, visible list is acceptable here; a silent skip is not.
UNDRIVABLE = {
    ("GET", V1 + "/gdpr/schema/"):
        "Serves a freshly generated OpenAPI document; drf-spectacular binds "
        "each view's schema class at IMPORT time from DEFAULT_SCHEMA_CLASS, "
        "which the suite's permissive REST_FRAMEWORK does not set, so the "
        "generator refuses in-process whatever the test overrides afterwards.",
}


# ── admin / capabilities ─────────────────────────────────────────────────────


@recipe("POST", "/admin-users/")
def _admin_users_create(call):
    return call(
        client_for(make_staff()),
        data={"email": f"{_unique('brokered-')}@example.com", "username": _unique("brk_")},
    )


@recipe("GET", "/admin/audit/")
def _admin_audit(call):
    staff = make_staff()
    make_audit_entry(staff)
    return call(client_for(staff))


@recipe("GET", "/capabilities/")
def _capabilities(call):
    return call(anonymous())


@recipe("GET", "/service-keys")
def _service_keys_list(call):
    service_key()
    return call(client_for(make_staff()))


@recipe("POST", "/service-keys")
def _service_keys_create(call):
    return call(client_for(make_staff()), data={"name": _unique("wire-key-")})


@recipe("GET", "/service-keys/{id}")
def _service_keys_get(call):
    from stapel_auth.models import ServiceAPIKey

    service_key()
    row = ServiceAPIKey.objects.get()
    return call(client_for(make_staff()), params={"id": row.pk})


@recipe("PUT", "/service-keys/{id}")
def _service_keys_put(call):
    from stapel_auth.models import ServiceAPIKey

    service_key()
    row = ServiceAPIKey.objects.get()
    return call(
        client_for(make_staff()), params={"id": row.pk}, data={"name": "renamed by wire"}
    )


@recipe("PATCH", "/service-keys/{id}")
def _service_keys_patch(call):
    from stapel_auth.models import ServiceAPIKey

    service_key()
    row = ServiceAPIKey.objects.get()
    return call(
        client_for(make_staff()), params={"id": row.pk}, data={"description": "wire"}
    )


@recipe("GET", "/staff-roles/")
def _staff_roles_list(call):
    from stapel_auth.staff_roles import assign_staff_role

    root = make_staff()
    assign_staff_role(make_user(is_staff=True), "editor")
    return call(client_for(root))


@recipe("POST", "/staff-roles/")
def _staff_roles_assign(call):
    root = make_staff()
    target = make_user(is_staff=True)
    return call(client_for(root), data={"user_id": str(target.pk), "role": "editor"})


# ── anonymous / me / logout / verify ─────────────────────────────────────────


@recipe("POST", "/anonymous/")
def _anonymous(call):
    return call(anonymous(), data={"device_id": _unique("device-")})


@recipe("GET", "/me/")
def _me(call):
    return call(client_for(make_user()))


@recipe("GET", "/logout/")
def _logout_get(call):
    return call(client_for(make_user()))


@recipe("POST", "/logout/")
def _logout_post(call):
    tokens = otp_login()["tokens"]
    client = anonymous()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {tokens['access']}")
    return call(client, data={"refresh_token": tokens["refresh"]})


@recipe("POST", "/verify/")
def _verify_token(call):
    access, _ = jwt_provider.create_tokens(make_user())
    return call(anonymous(), data={"token": access})


# ── email / phone OTP ────────────────────────────────────────────────────────


@recipe("POST", "/email/request/")
def _email_request(call):
    return call(anonymous(), data={"email": f"{_unique('wire-')}@example.com"})


@recipe("POST", "/email/verify/")
def _email_verify(call):
    client = anonymous()
    email = f"{_unique('wire-')}@example.com"
    assert client.post(f"{V1}/email/request/", {"email": email}).status_code == 200
    return call(client, data={"email": email, "code": OTP_CODE})


@recipe("POST", "/phone/request/")
def _phone_request(call):
    return call(anonymous(), data={"phone": "+12025550{:03d}".format(uuid.uuid4().int % 1000)})


@recipe("POST", "/phone/verify/")
def _phone_verify(call):
    client = anonymous()
    phone = "+12025551{:03d}".format(uuid.uuid4().int % 1000)
    assert client.post(f"{V1}/phone/request/", {"phone": phone}).status_code == 200
    return call(client, data={"phone": phone, "code": OTP_CODE})


# ── authenticator change: email / phone, instant + delayed ───────────────────


def _instant_request_old(call, kind):
    user = make_user(phone="+12025552001", is_phone_verified=True)
    return call(client_for(user))


def _instant_verify_old(call, kind):
    user = make_user(phone="+12025552002", is_phone_verified=True)
    client = client_for(user)
    assert client.post(f"{V1}/{kind}/change/instant/request-old/", {}).status_code == 200
    return call(client, data={"code": OTP_CODE})


def _instant_request_new(call, kind, new_value):
    user = make_user(phone="+12025552003", is_phone_verified=True)
    client = client_for(user)
    token = instant_change_token(client, kind)
    return call(client, data={kind: new_value, "change_token": token})


def _instant_verify_new(call, kind, new_value):
    user = make_user(phone="+12025552004", is_phone_verified=True)
    client = client_for(user)
    token = instant_change_token(client, kind)
    assert client.post(
        f"{V1}/{kind}/change/instant/request-new/",
        {kind: new_value, "change_token": token},
        format="json",
    ).status_code == 200
    return call(client, data={kind: new_value, "code": OTP_CODE, "change_token": token})


@recipe("POST", "/email/change/instant/request-old/")
def _email_instant_request_old(call):
    return _instant_request_old(call, "email")


@recipe("POST", "/email/change/instant/verify-old/")
def _email_instant_verify_old(call):
    return _instant_verify_old(call, "email")


@recipe("POST", "/email/change/instant/request-new/")
def _email_instant_request_new(call):
    return _instant_request_new(call, "email", f"{_unique('new-')}@example.com")


@recipe("POST", "/email/change/instant/verify-new/")
def _email_instant_verify_new(call):
    return _instant_verify_new(call, "email", f"{_unique('new-')}@example.com")


@recipe("POST", "/phone/change/instant/request-old/")
def _phone_instant_request_old(call):
    return _instant_request_old(call, "phone")


@recipe("POST", "/phone/change/instant/verify-old/")
def _phone_instant_verify_old(call):
    return _instant_verify_old(call, "phone")


@recipe("POST", "/phone/change/instant/request-new/")
def _phone_instant_request_new(call):
    return _instant_request_new(call, "phone", "+13125553001")


@recipe("POST", "/phone/change/instant/verify-new/")
def _phone_instant_verify_new(call):
    return _instant_verify_new(call, "phone", "+13125553002")


def _delayed_initiate(call, new_field, new_value):
    user = make_user(phone="+12025554001", is_phone_verified=True)
    return call(client_for(user), data={new_field: new_value})


def _delayed_status(call, kind, new_field, new_value):
    user = make_user(phone="+12025554002", is_phone_verified=True)
    client = client_for(user)
    assert client.post(
        f"{V1}/{kind}/change/delayed/initiate/", {new_field: new_value}, format="json"
    ).status_code == 201
    return call(client)


def _delayed_cancel(call, kind, new_field, new_value):
    user = make_user(phone="+12025554003", is_phone_verified=True)
    client = client_for(user)
    started = client.post(
        f"{V1}/{kind}/change/delayed/initiate/", {new_field: new_value}, format="json"
    )
    assert started.status_code == 201, started.content
    return call(client, data={"change_request_id": started.json()["change_request_id"]})


@recipe("POST", "/email/change/delayed/initiate/")
def _email_delayed_initiate(call):
    return _delayed_initiate(call, "email", f"{_unique('delayed-')}@example.com")


@recipe("GET", "/email/change/delayed/status/")
def _email_delayed_status(call):
    return _delayed_status(call, "email", "email", f"{_unique('delayed-')}@example.com")


@recipe("POST", "/email/change/delayed/cancel/")
def _email_delayed_cancel(call):
    return _delayed_cancel(call, "email", "email", f"{_unique('delayed-')}@example.com")


@recipe("POST", "/phone/change/delayed/initiate/")
def _phone_delayed_initiate(call):
    return _delayed_initiate(call, "phone", "+13125554001")


@recipe("GET", "/phone/change/delayed/status/")
def _phone_delayed_status(call):
    return _delayed_status(call, "phone", "phone", "+13125554002")


@recipe("POST", "/phone/change/delayed/cancel/")
def _phone_delayed_cancel(call):
    return _delayed_cancel(call, "phone", "phone", "+13125554003")


# ── login grant / magic link / oauth / introspection ─────────────────────────


@recipe("POST", "/grant/exchange/")
def _grant_exchange(call):
    from stapel_auth.login_grant.services import issue_login_grant

    user = make_user()
    with override_settings(STAPEL_AUTH={"AUTH_LOGIN_GRANT": True}):
        token = issue_login_grant(email=user.email)
        return call(anonymous(), data={"grant_token": token})


@recipe("POST", "/magic/request/")
def _magic_request(call):
    return call(anonymous(), data={"email": make_user().email})


@recipe("GET", "/oauth/links/")
def _oauth_links_list(call):
    from stapel_auth.models import LinkedOAuthAccount

    user = make_user()
    LinkedOAuthAccount.objects.create(user=user, provider="github", provider_user_id="gh-1")
    return call(client_for(user))


@recipe("POST", "/oauth/links/")
def _oauth_links_link(call):
    from stapel_auth.oauth_providers import OAuthUserData

    user = make_user()
    with patch(
        "stapel_auth.oauth.services.OAuthService.get_user_data",
        return_value=OAuthUserData(
            id=_unique("g-"), email=f"{_unique('linked-')}@example.com",
            username=_unique("linked_"), avatar=None, email_verified=True,
        ),
    ):
        return call(client_for(user), data={"provider": "google", "access_token": "tok"})


@recipe("POST", "/oauth/login/")
def _oauth_login(call):
    from stapel_auth.oauth_providers import OAuthUserData

    with patch(
        "stapel_auth.oauth.services.OAuthService.get_user_data",
        return_value=OAuthUserData(
            id=_unique("g-"), email=f"{_unique('oauth-')}@example.com",
            username=_unique("oauth_"), avatar=None, email_verified=True,
        ),
    ):
        return call(anonymous(), data={"provider": "google", "access_token": "tok"})


@recipe("POST", "/oauth2/introspect/")
def _introspect(call):
    access, _ = jwt_provider.create_tokens(make_user())
    return call(anonymous(), data={"token": access}, HTTP_X_API_KEY=service_key())


# ── mfa: totp, passkeys, enroll exchange ─────────────────────────────────────


@recipe("POST", "/totp/setup/")
def _totp_setup(call):
    return call(client_for(make_user()))


@recipe("POST", "/totp/setup/confirm/")
def _totp_setup_confirm(call):
    import pyotp

    from stapel_auth.mfa.services import TOTPService

    user = make_user()
    client = client_for(user)
    started = client.post(f"{V1}/totp/setup/", {}, format="json")
    assert started.status_code == 200, started.content
    code = pyotp.TOTP(
        started.json()["secret"], digits=TOTPService.CODE_LENGTH
    ).now()
    return call(client, data={"code": code})


@recipe("POST", "/totp/change/delayed/initiate/")
def _totp_delayed_initiate(call):
    user = make_user()
    enable_totp(user)
    return call(client_for(user), data={"device_id": _unique("device-")})


@recipe("GET", "/totp/change/delayed/status/")
def _totp_delayed_status(call):
    user = make_user()
    enable_totp(user)
    client = client_for(user)
    assert client.post(f"{V1}/totp/change/delayed/initiate/", {}, format="json").status_code == 201
    return call(client)


@recipe("POST", "/totp/change/delayed/cancel/")
def _totp_delayed_cancel(call):
    user = make_user()
    enable_totp(user)
    client = client_for(user)
    started = client.post(f"{V1}/totp/change/delayed/initiate/", {}, format="json")
    assert started.status_code == 201, started.content
    return call(client, data={"change_request_id": started.json()["change_request_id"]})


@recipe("GET", "/passkey/")
def _passkey_list(call):
    user = make_user()
    make_passkey(user)
    return call(client_for(user))


@recipe("PATCH", "/passkey/{id}/")
def _passkey_rename(call):
    user = make_user()
    credential = make_passkey(user)
    return call(
        client_for(user), params={"id": credential.id}, data={"device_name": "Work laptop"}
    )


@recipe("POST", "/passkey/register/begin/")
def _passkey_register_begin(call):
    return call(client_for(make_user()))


@recipe("POST", "/passkey/authenticate/begin/")
def _passkey_authenticate_begin(call):
    user = make_user()
    make_passkey(user)
    return call(anonymous(), data={"email": user.email})


@recipe("POST", "/passkey/register/complete/")
def _passkey_register_complete(call):
    """The authenticator's signature is mocked; the response path is not.

    ``registration_complete`` is the one step that needs a real device to
    produce a verifiable attestation. Everything this gate is about — the
    serializer that renders the stored credential — runs for real.
    """
    user = make_user()
    credential = make_passkey(user, device_name="My Phone")
    with patch(
        "stapel_auth.mfa.services.PasskeyService.registration_complete",
        return_value=credential,
    ):
        return call(
            client_for(user), data={"credential": {"id": "abc"}, "device_name": "My Phone"}
        )


@recipe("POST", "/mfa/enroll/exchange/")
def _mfa_enroll_exchange(call):
    with password_on():
        user = provisioned_user(mfa_enrollment_required=True)
        token = first_login_challenge(user, "mfa_enroll")
        return call(anonymous(), data={"challenge_token": token})


# ── password ─────────────────────────────────────────────────────────────────


@recipe("POST", "/password/login/")
def _password_login(call):
    with password_on():
        user = make_user()
        return call(anonymous(), data={"login": user.username, "password": PASSWORD})


@recipe("GET", "/password/methods/")
def _password_methods(call):
    with password_on():
        return call(client_for(make_user()))


@recipe("POST", "/password/register/")
def _password_register(call):
    with password_on():
        return call(
            anonymous(),
            data={
                "email": f"{_unique('pwreg-')}@example.com",
                "username": _unique("pwreg_"),
                "password": PASSWORD,
            },
        )


@recipe("POST", "/password/forced-change/")
def _password_forced_change(call):
    with password_on():
        user = provisioned_user(password_change_required=True)
        token = first_login_challenge(user, "password_change")
        return call(
            anonymous(),
            data={"challenge_token": token, "new_password": "another-wire-password-9"},
        )


@recipe("POST", "/password/change/otp/request/")
def _password_change_otp_request(call):
    with password_on():
        return call(client_for(make_user()), data={"method": "email"})


@recipe("POST", "/password/change/otp/verify/")
def _password_change_otp_verify(call):
    with password_on():
        client = client_for(make_user())
        assert client.post(
            f"{V1}/password/change/otp/request/", {"method": "email"}, format="json"
        ).status_code == 200
        return call(
            client,
            data={"method": "email", "code": OTP_CODE, "new_password": "another-wire-password-9"},
        )


@recipe("POST", "/password/reset/email/request/")
def _password_reset_email_request(call):
    with password_on():
        return call(anonymous(), data={"email": make_user().email})


@recipe("POST", "/password/reset/email/verify/")
def _password_reset_email_verify(call):
    with password_on():
        client = anonymous()
        user = make_user()
        assert client.post(
            f"{V1}/password/reset/email/request/", {"email": user.email}, format="json"
        ).status_code == 200
        return call(
            client,
            data={
                "email": user.email,
                "code": OTP_CODE,
                "new_password": "another-wire-password-9",
            },
        )


@recipe("POST", "/password/reset/phone/request/")
def _password_reset_phone_request(call):
    with password_on():
        make_user(phone="+12025556001", is_phone_verified=True)
        return call(anonymous(), data={"phone": "+12025556001"})


@recipe("POST", "/password/reset/phone/verify/")
def _password_reset_phone_verify(call):
    with password_on():
        client = anonymous()
        make_user(phone="+12025556002", is_phone_verified=True)
        assert client.post(
            f"{V1}/password/reset/phone/request/", {"phone": "+12025556002"}, format="json"
        ).status_code == 200
        return call(
            client,
            data={
                "phone": "+12025556002",
                "code": OTP_CODE,
                "new_password": "another-wire-password-9",
            },
        )


@recipe("POST", "/token/")
def _legacy_token(call):
    with password_on(AUTH_LEGACY_TOKEN_LOGIN=True):
        user = make_user()
        return call(anonymous(), data={"username": user.username, "password": PASSWORD})


# ── qr ───────────────────────────────────────────────────────────────────────


@recipe("POST", "/qr/generate/")
def _qr_generate(call):
    return call(anonymous(), data={"type": "login_request"})


@recipe("GET", "/qr/{key}/status/")
def _qr_status(call):
    # The polling device is the one that generated the key (the view refuses
    # a poll from any other device), so one client does both halves.
    client = anonymous()
    return call(client, params={"key": qr_key(client)})


@recipe("POST", "/qr/{key}/confirm/")
def _qr_confirm(call):
    return call(client_for(make_user()), params={"key": qr_key()})


@recipe("POST", "/qr/{key}/reject/")
def _qr_reject(call):
    return call(client_for(make_user()), params={"key": qr_key()})


# ── security / sessions / tokens ─────────────────────────────────────────────


@recipe("GET", "/security/status/")
def _security_status(call):
    return call(client_for(make_user()))


@recipe("GET", "/security/audit/")
def _security_audit(call):
    user = make_user()
    make_audit_entry(user)
    return call(client_for(user))


@recipe("GET", "/sessions/")
def _sessions_list(call):
    user = make_user()
    make_session(user)
    return call(client_for(user))


@recipe("POST", "/sessions/{session_id}/confirm/")
def _session_confirm(call):
    user = make_user()
    session = make_session(user, is_suspicious=True)
    return call(client_for(user), params={"session_id": session.id})


@recipe("POST", "/token/refresh/")
def _token_refresh_post(call):
    return call(anonymous(), data={"refresh": otp_login()["tokens"]["refresh"]})


@recipe("GET", "/token/refresh/")
def _token_refresh_get(call):
    """The cookie path: GET takes no body, so the session must ride a cookie."""
    from django.conf import settings

    tokens = otp_login()["tokens"]
    client = anonymous()
    client.cookies[getattr(settings, "JWT_REFRESH_COOKIE_NAME", "stapel_refresh_jwt")] = (
        tokens["refresh"]
    )
    return call(client)


# ── sso ──────────────────────────────────────────────────────────────────────


@recipe("GET", "/sso/lookup/")
def _sso_lookup(call):
    org = make_org()
    return call(anonymous(), query=f"?domain={org.domain}")


@recipe("GET", "/sso/orgs/")
def _sso_orgs_list(call):
    make_org()
    return call(client_for(make_staff()))


@recipe("POST", "/sso/orgs/")
def _sso_orgs_create(call):
    slug = _unique("org")
    return call(
        client_for(make_staff()),
        data={"name": "Wire Org", "slug": slug, "domain": f"{slug}.example.com"},
    )


@recipe("GET", "/sso/orgs/{slug}/")
def _sso_org_get(call):
    return call(client_for(make_staff()), params={"slug": make_org().slug})


@recipe("PATCH", "/sso/orgs/{slug}/")
def _sso_org_patch(call):
    return call(
        client_for(make_staff()),
        params={"slug": make_org().slug},
        data={"sso_enforced": True},
    )


@recipe("PUT", "/sso/orgs/{slug}/config/")
def _sso_org_config_put(call):
    return call(
        client_for(make_staff()),
        params={"slug": make_org().slug},
        data={
            "protocol": "saml",
            "is_active": True,
            "saml_entity_id": "https://idp.example.com",
            "saml_sso_url": "https://idp.example.com/sso",
            "saml_x509_cert": "MIID...",
        },
    )


@recipe("PATCH", "/sso/orgs/{slug}/config/")
def _sso_org_config_patch(call):
    staff = make_staff()
    org = make_org()
    client = client_for(staff)
    assert client.put(
        f"{V1}/sso/orgs/{org.slug}/config/",
        {"protocol": "saml", "is_active": True, "saml_entity_id": "https://idp.example.com"},
        format="json",
    ).status_code == 200
    return call(client, params={"slug": org.slug}, data={"is_active": False})


# ── verification (step-up) ───────────────────────────────────────────────────


@recipe("GET", "/verification/{challenge_id}/")
def _verification_info(call):
    user = make_user()
    return call(client_for(user), params={"challenge_id": challenge_for(user)})


@recipe("POST", "/verification/{challenge_id}/initiate/")
def _verification_initiate(call):
    user = make_user()
    return call(
        client_for(user),
        params={"challenge_id": challenge_for(user)},
        data={"factor": "otp_email"},
    )


@recipe("POST", "/verification/{challenge_id}/complete/")
def _verification_complete(call):
    user = make_user()
    client = client_for(user)
    challenge_id = challenge_for(user)
    assert client.post(
        f"{V1}/verification/{challenge_id}/initiate/", {"factor": "otp_email"}, format="json"
    ).status_code == 200
    return call(
        client, params={"challenge_id": challenge_id},
        data={"factor": "otp_email", "code": OTP_CODE},
    )


@recipe("GET", "/verification/preferences/")
def _verification_preferences_list(call):
    from stapel_auth.models import VerificationPreference

    user = make_user()
    VerificationPreference.objects.create(user=user, scope="wire_contract", enabled=True)
    return call(client_for(user))


@recipe("PUT", "/verification/preferences/")
def _verification_preferences_put(call):
    return call(
        client_for(make_user()), data={"scope": "wire_contract", "enabled": True}
    )


# ── gdpr (mounted beside auth, same as the emission harness) ─────────────────


@recipe("POST", "/dsar")
def _dsar_create(call):
    return call(
        anonymous(),
        data={"kind": "access", "email": f"{_unique('dsar-')}@example.com"},
    )


@recipe("GET", "/dsar")
def _dsar_list(call):
    dsar_row()
    return call(client_for(make_staff()))


@recipe("GET", "/dsar/{dsar_id}")
def _dsar_get(call):
    return call(client_for(make_staff()), params={"dsar_id": dsar_row()})


@recipe("PATCH", "/dsar/{dsar_id}")
def _dsar_patch(call):
    return call(
        client_for(make_staff()),
        params={"dsar_id": dsar_row()},
        data={"note": "triaged by the wire gate"},
    )


@recipe("POST", "/erasures")
def _erasure_create(call):
    with gdpr_settings():
        return call(
            client_for(make_staff()),
            data={"subject_type": "account", "subject_key": _unique("subject-")},
        )


@recipe("GET", "/erasures/{request_id}")
def _erasure_status(call):
    with gdpr_settings():
        staff = make_staff()
        client = client_for(staff)
        opened = client.post(
            f"{V1}/erasures",
            {"subject_type": "account", "subject_key": _unique("subject-")},
            format="json",
        )
        assert opened.status_code == 202, opened.content
        return call(client, params={"request_id": opened.json()["request_id"]})


@recipe("GET", "/me/erasures")
def _my_erasures(call):
    with gdpr_settings():
        # The list is keyed on who OPENED the erasure, and opening one is
        # staff-only (the default ERASURE_AUTHORIZER).
        client = client_for(make_staff())
        opened = client.post(
            f"{V1}/erasures",
            {"subject_type": "account", "subject_key": _unique("subject-")},
            format="json",
        )
        assert opened.status_code == 202, opened.content
        return call(client)


@recipe("GET", "/owners/health")
def _owners_health(call):
    with gdpr_settings():
        return call(client_for(make_staff()))


@recipe("POST", "/user/account/close")
def _account_close(call):
    with gdpr_settings():
        return call(client_for(make_user()))


@recipe("GET", "/user/account/close/status")
def _account_close_status(call):
    with gdpr_settings():
        token = closed_account()
        return call(anonymous(), HTTP_X_CLOSURE_TOKEN=token)


@recipe("POST", "/user/account/cancel-close")
def _account_cancel_close(call):
    with gdpr_settings():
        token = closed_account()
        return call(anonymous(), HTTP_X_CLOSURE_TOKEN=token)


@recipe("POST", "/user/data-export/request")
def _export_request(call):
    with gdpr_settings():
        return call(client_for(make_user()))


@recipe("GET", "/user/data-export/status")
def _export_status(call):
    with gdpr_settings():
        client = client_for(make_user())
        opened = client.post(f"{V1}/user/data-export/request", {}, format="json")
        assert opened.status_code == 202, opened.content
        return call(client)


# ─────────────────────────────────────────────────────────────────────────────
# The gate
# ─────────────────────────────────────────────────────────────────────────────


def test_the_contract_declares_something_to_check():
    assert OPERATIONS, "docs/schema.json declares no JSON responses at all"


def test_every_declared_operation_is_driven_or_named_undrivable():
    """No operation is covered by silence, and no entry outlives its operation."""
    declared = {(method, path) for method, path, _, _ in OPERATIONS}
    covered = set(RECIPES) | set(UNDRIVABLE)

    missing = sorted(declared - covered)
    assert not missing, (
        "operations with a declared JSON response body and no recipe:\n"
        + "\n".join(f"  {m} {p}" for m, p in missing)
    )
    stale = sorted(covered - declared)
    assert not stale, (
        "recipes/exclusions for operations the contract no longer declares:\n"
        + "\n".join(f"  {m} {p}" for m, p in stale)
    )
    both = sorted(set(RECIPES) & set(UNDRIVABLE))
    assert not both, f"driven AND excluded: {both}"
    for key, reason in UNDRIVABLE.items():
        assert reason and reason.strip(), f"{key} is excluded with no reason"


def test_every_known_mismatch_is_still_declared_and_explained():
    """A recorded defect must name a live operation and carry its reason.

    Without this, an operation that is renamed or removed leaves an entry that
    silences nothing and reads like a known problem forever.
    """
    declared = {(method, path) for method, path, _code, _schema in OPERATIONS}
    for key, reason in KNOWN_MISMATCHES.items():
        assert key in declared, (
            f"{key} is recorded as a known mismatch but the contract no longer "
            "declares it - delete the entry"
        )
        assert reason and reason.strip(), f"{key} is recorded with no reason"


#: Operations whose declared body the wire does not send.
#:
#: EMPTY, and that is the point: both entries this gate found on the day it was
#: written were fixed rather than exempted (introspect now decodes the real
#: claims; SecurityStatusTOTP.backup_codes_remaining is `int | None`, matching
#: the service that fills it). The mechanism stays because the next wave will
#: need it: an entry must name the defect and its owner, and `strict=True`
#: turns a fixed one into a failure until the entry is deleted, so a finding
#: can be neither forgotten nor quietly kept.
KNOWN_MISMATCHES: dict = {}


@pytest.mark.parametrize(
    "method,path,code,body_schema",
    OPERATIONS,
    ids=[f"{m} {p}" for m, p, _, _ in OPERATIONS],
)
def test_the_wire_matches_the_declared_response(method, path, code, body_schema, request):
    if (method, path) in UNDRIVABLE:
        pytest.skip(f"excluded by name: {UNDRIVABLE[(method, path)]}")

    if (method, path) in KNOWN_MISMATCHES:
        request.node.add_marker(
            pytest.mark.xfail(
                strict=True,
                reason=f"{method} {path}: {KNOWN_MISMATCHES[(method, path)]}",
            )
        )

    perform = RECIPES.get((method, path))
    assert perform is not None, (
        f"{method} {path} declares a response body and has no recipe — an "
        "unchecked operation is a schema nobody proves. Teach RECIPES, or "
        "name it in UNDRIVABLE with a reason."
    )

    response = perform(Call(method, path))
    assert response.status_code == code, (
        f"{method} {path}: expected the declared {code}, got "
        f"{response.status_code}: {response.content[:400]}"
    )

    body = response.json()
    errors = sorted(_validator(body_schema).iter_errors(body), key=lambda e: list(e.path))
    assert not errors, (
        f"{method} {path} answers a body the contract does not describe:\n"
        + "\n".join(f"  at {list(e.path) or '<root>'}: {e.message}" for e in errors[:10])
        + f"\n  body: {json.dumps(body)[:600]}"
    )
    # An empty list validates against any item schema, so a list response must
    # actually carry a row for the check to have looked at anything.
    if isinstance(body, list):
        assert body, f"{method} {path}: the declared list came back empty"
