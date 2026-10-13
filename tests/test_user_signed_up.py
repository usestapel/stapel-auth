"""``user.signed_up``: one milestone per account, at every self-serve door.

``user.registered`` fires at creation, guests included, so a reporter that
wants "a person signed up" cannot use it: it counts guests, misses the guest
promoted on the same row, and the phone door never announced at all. These
tests hold the replacement to its rule:

* one event at each self-serve door, fresh and promoted;
* none for guest enrolment, LOGGED_IN, MERGED, MODIFIED, a password-only
  account, org provisioning, a login grant, enterprise SSO or a staff-made
  account;
* never two for one account;
* ``ad_consent`` is the host resolver's answer, ``unknown`` without one and
  ``denied`` when it raises, and the registration succeeds either way;
* a door added later without the emit fails :class:`TestDoorInventory`.
"""
import ast
import datetime
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

import stapel_auth
from stapel_core.comm import call
from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.models import Organization, UserSignup
from stapel_auth.oauth_providers import OAuthUserData
from stapel_auth.signup import SignupConsent, notify_user_signed_up

User = get_user_model()

PASSWORD_ON = {"AUTH_PASSWORD_REGISTRATION": True}

_RESOLVER_CALLS = []


def recording_resolver(request):
    """A host resolver: records what it was handed, answers granted."""
    _RESOLVER_CALLS.append(request)
    return SignupConsent("granted", "banner_accepted")


def pair_resolver(request):
    return ("denied", "privacy_header")


def raising_resolver(request):
    raise RuntimeError("consent store down")


def nonsense_resolver(request):
    return SignupConsent("maybe", "typo")


def _signed_up(user_id=None):
    payloads = [
        json.loads(row.event_json)["payload"]
        for row in OutboxEvent.objects.filter(topic="user.signed_up")
    ]
    if user_id is None:
        return payloads
    return [p for p in payloads if p["user_id"] == str(user_id)]


def _bearer(user) -> APIClient:
    from stapel_core.django.jwt.provider import jwt_provider

    access, _ = jwt_provider.create_tokens(user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return client


def _email_verify(client, email):
    with patch(
        "stapel_auth.otp.services.EmailVerificationService.verify_code",
        return_value={"success": True},
    ):
        return client.post(
            reverse("email_verify"), {"email": email, "code": "1234"}, format="json"
        )


def _phone_verify(client, phone):
    with patch(
        "stapel_auth.otp.services.PhoneVerificationService.verify_code",
        return_value={"success": True},
    ):
        return client.post(
            reverse("phone_verify"), {"phone": phone, "code": "1234"}, format="json"
        )


def _oauth_login(client, uid, email):
    with patch(
        "stapel_auth.oauth.services.OAuthService.get_user_data",
        return_value=OAuthUserData(
            id=uid, email=email, username=uid, avatar=None, email_verified=True
        ),
    ):
        return client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "tok"},
            format="json",
        )


def _schema():
    path = Path(stapel_auth.__file__).parent / "schemas" / "emits" / "user.signed_up.json"
    return json.loads(path.read_text())


@pytest.fixture(autouse=True)
def _clean():
    cache.clear()
    _RESOLVER_CALLS.clear()


# ── The doors that are sign-ups ─────────────────────────────────────────────


@pytest.mark.django_db
class TestFreshAccounts:
    def test_email_otp(self):
        resp = _email_verify(APIClient(), "fresh-mail@shop.example")
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(resp.data["user"]["id"])
        assert payload["auth_type"] == "email"
        assert payload["was_guest"] is False

    def test_phone_otp(self):
        resp = _phone_verify(APIClient(), "+12025550111")
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(resp.data["user"]["id"])
        assert payload["auth_type"] == "phone"
        assert payload["was_guest"] is False

    def test_oauth_hands_the_request_to_the_resolver(self):
        with override_settings(
            STAPEL_AUTH={"AUTH_SIGNUP_CONSENT_RESOLVER": f"{__name__}.recording_resolver"}
        ):
            resp = _oauth_login(APIClient(), "uid-fresh", "fresh-oauth@shop.example")
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(resp.data["user"]["id"])
        assert payload["auth_type"] == "oauth"
        assert payload["ad_consent"] == "granted"
        assert payload["consent_source"] == "banner_accepted"
        assert len(_RESOLVER_CALLS) == 1
        assert _RESOLVER_CALLS[0] is not None
        assert _RESOLVER_CALLS[0].path == reverse("oauth_login")

    @override_settings(STAPEL_AUTH=PASSWORD_ON)
    def test_password_with_email(self):
        resp = APIClient().post(
            reverse("password_register"),
            {"email": "pw-mail@shop.example", "password": "brandnew456!"},
        )
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(resp.data["user"]["id"])
        assert payload["was_guest"] is False

    def test_payload_shape(self):
        before = datetime.datetime.now(datetime.timezone.utc)
        resp = _email_verify(APIClient(), "shape@shop.example")
        [payload] = _signed_up(resp.data["user"]["id"])

        import jsonschema

        jsonschema.validate(payload, _schema())
        assert payload["registered_at"].endswith("Z")
        at = datetime.datetime.fromisoformat(payload["registered_at"].replace("Z", "+00:00"))
        assert at.utcoffset() == datetime.timedelta(0)
        assert before <= at <= datetime.datetime.now(datetime.timezone.utc)
        assert payload["is_staff"] is False
        assert UserSignup.objects.get(user_id=payload["user_id"]).registered_at == at

    def test_is_staff_is_reported(self):
        user = User.objects.create(email="staff@shop.example", auth_type="email", is_staff=True)
        notify_user_signed_up(user, was_guest=False)
        [payload] = _signed_up(user.id)
        assert payload["is_staff"] is True


@pytest.mark.django_db
class TestPromotedGuests:
    def test_email_otp(self):
        guest = User.create_anonymous_user()
        resp = _email_verify(_bearer(guest), "promo-mail@shop.example")
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(guest.id)
        assert payload["was_guest"] is True
        assert payload["auth_type"] == "email"

    def test_phone_otp(self):
        guest = User.create_anonymous_user()
        resp = _phone_verify(_bearer(guest), "+12025550122")
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(guest.id)
        assert payload["was_guest"] is True

    def test_oauth(self):
        guest = User.create_anonymous_user()
        resp = _oauth_login(_bearer(guest), "uid-promo", "promo-oauth@shop.example")
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(guest.id)
        assert payload["was_guest"] is True
        assert payload["auth_type"] == "oauth"

    @override_settings(STAPEL_AUTH=PASSWORD_ON)
    def test_password_with_email(self):
        guest = User.create_anonymous_user()
        resp = _bearer(guest).post(
            reverse("password_register"),
            {"email": "promo-pw@shop.example", "password": "brandnew456!"},
        )
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(guest.id)
        assert payload["was_guest"] is True

    @override_settings(
        STAPEL_AUTH={**PASSWORD_ON, "AUTH_PASSWORD_DEANONYMIZES": True}
    )
    def test_password_only_where_a_password_is_an_identity(self):
        guest = User.create_anonymous_user()
        resp = _bearer(guest).post(
            reverse("password_register"),
            {"password": "brandnew456!", "username": "classic_acme"},
        )
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(guest.id)
        assert payload["auth_type"] == "password"

    def test_change_via_otp_promotion(self):
        guest = User.create_anonymous_user()
        guest.email = "promo-change@shop.example"
        guest.is_email_verified = True
        guest.save()
        with patch(
            "stapel_auth.otp.services.EmailVerificationService.verify_code",
            return_value={"success": True},
        ):
            resp = _bearer(guest).post(
                reverse("password_change_otp_verify"),
                {"method": "email", "code": "1234", "new_password": "brandnew456!"},
            )
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(guest.id)
        assert payload["was_guest"] is True


# ── The answers that are not sign-ups ───────────────────────────────────────


@pytest.mark.django_db
class TestNotASignup:
    def test_guest_enrolment(self):
        resp = APIClient().post(reverse("anonymous"), {}, format="json")
        assert resp.status_code == 201
        assert _signed_up() == []

    def test_logged_in(self):
        User.objects.create(email="back@shop.example", auth_type="email", is_email_verified=True)
        resp = _email_verify(APIClient(), "back@shop.example")
        assert resp.data["status"] == "LOGGED_IN"
        assert _signed_up() == []

    def test_merged(self):
        User.objects.create(email="taken@shop.example", auth_type="email", is_email_verified=True)
        guest = User.create_anonymous_user()
        resp = _email_verify(_bearer(guest), "taken@shop.example")
        assert resp.data["status"] == "MERGED"
        assert _signed_up() == []

    def test_modified_account_adds_an_address(self):
        user = User.objects.create_user(username="has_phone", phone="+12025550133", is_phone_verified=True)
        resp = _email_verify(_bearer(user), "added@shop.example")
        assert resp.data["status"] == "MODIFIED"
        assert _signed_up() == []

    @override_settings(STAPEL_AUTH=PASSWORD_ON)
    def test_modified_guest_adds_a_password(self):
        guest = User.create_anonymous_user()
        resp = _bearer(guest).post(
            reverse("password_register"),
            {"password": "brandnew456!", "username": "portable_acme"},
        )
        assert resp.data["status"] == "MODIFIED"
        assert _signed_up() == []

    @override_settings(STAPEL_AUTH=PASSWORD_ON)
    def test_password_only_create(self):
        resp = APIClient().post(
            reverse("password_register"),
            {"password": "brandnew456!", "username": "just_a_login"},
        )
        assert resp.data["status"] == "REGISTERED"
        assert _signed_up() == []

    def test_provision_user(self):
        result = call("auth.provision_user", {
            "username": "acme/bob",
            "password": "correct-horse-battery-staple-9",
            "first_login_policies": [],
        })
        assert "error" not in result, result
        assert _signed_up() == []

    def test_login_grant(self):
        from stapel_auth.login_grant.services import LoginGrantService, issue_login_grant

        token = issue_login_grant(email="invitee@shop.example", create_if_missing=True)
        _user, created = LoginGrantService.exchange(token)
        assert created
        assert _signed_up() == []

    def test_sso_create_and_guest_promotion(self):
        from stapel_auth.sso_service import SSOUserService

        org = Organization.objects.create(name="Acme", slug="acme", domain="acme.example")
        _user, created = SSOUserService.get_or_create_user(
            org, {"email": "a@acme.example", "first_name": "", "last_name": "", "subject_id": "s-1"}
        )
        assert created
        guest = User.create_anonymous_user()
        promoted, created = SSOUserService.get_or_create_user(
            org,
            {"email": "b@acme.example", "first_name": "", "last_name": "", "subject_id": "s-2"},
            request_user=guest,
        )
        assert created and promoted.pk == guest.pk
        assert _signed_up() == []

    def test_staff_created_account(self):
        staff = User.objects.create_user(username="ops", password="pw", is_staff=True)
        resp = _bearer(staff).post(
            reverse("admin-users"), {"email": "made@shop.example"}, format="json"
        )
        assert resp.status_code in (200, 201), resp.content
        assert _signed_up() == []


@pytest.mark.django_db
class TestOncePerAccount:
    def test_a_second_door_for_the_same_account_emits_nothing(self):
        resp = _email_verify(APIClient(), "twice@shop.example")
        user = User.objects.get(pk=resp.data["user"]["id"])
        notify_user_signed_up(user, was_guest=False)
        notify_user_signed_up(user, was_guest=True)
        assert len(_signed_up(user.id)) == 1
        assert UserSignup.objects.filter(user=user).count() == 1

    def test_a_failed_emit_does_not_fail_registration_and_leaves_no_marker(self):
        def _fail(name, *args, **kwargs):
            if name == "user.signed_up":
                raise RuntimeError("broker down")

        with patch("stapel_core.comm.emit", side_effect=_fail):
            resp = _email_verify(APIClient(), "broker@shop.example")
        assert resp.status_code == 200
        assert resp.data["status"] == "REGISTERED"
        assert not UserSignup.objects.filter(user_id=resp.data["user"]["id"]).exists()


# ── Consent ─────────────────────────────────────────────────────────────────


@pytest.mark.django_db
class TestConsent:
    def test_default_is_unknown(self):
        resp = _email_verify(APIClient(), "nores@shop.example")
        [payload] = _signed_up(resp.data["user"]["id"])
        assert payload["ad_consent"] == "unknown"
        assert payload["consent_source"] == "no_resolver"

    def test_a_pair_passes_through(self):
        with override_settings(
            STAPEL_AUTH={"AUTH_SIGNUP_CONSENT_RESOLVER": f"{__name__}.pair_resolver"}
        ):
            resp = _email_verify(APIClient(), "pair@shop.example")
        [payload] = _signed_up(resp.data["user"]["id"])
        assert (payload["ad_consent"], payload["consent_source"]) == ("denied", "privacy_header")

    @pytest.mark.parametrize("resolver", ["raising_resolver", "nonsense_resolver", "does_not_exist"])
    def test_a_failing_resolver_denies_and_registration_succeeds(self, resolver):
        with override_settings(
            STAPEL_AUTH={"AUTH_SIGNUP_CONSENT_RESOLVER": f"{__name__}.{resolver}"}
        ):
            resp = _email_verify(APIClient(), f"{resolver}@shop.example")
        assert resp.status_code == 200
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(resp.data["user"]["id"])
        assert payload["ad_consent"] == "denied"
        assert payload["consent_source"] == "resolver_error"

    def test_no_request_is_unknown_and_the_resolver_is_not_called(self):
        user = User.objects.create(email="norq@shop.example", auth_type="email")
        with override_settings(
            STAPEL_AUTH={"AUTH_SIGNUP_CONSENT_RESOLVER": f"{__name__}.recording_resolver"}
        ):
            notify_user_signed_up(user, was_guest=False)
        [payload] = _signed_up(user.id)
        assert (payload["ad_consent"], payload["consent_source"]) == ("unknown", "no_request")
        assert _RESOLVER_CALLS == []


# ── The inventory: a new door without the emit fails here ───────────────────

_USER_NAMES = {"User", "U", "UserModel"}
_CREATE = {"create", "create_user", "create_superuser", "get_or_create", "update_or_create", "bulk_create"}

#: Self-serve doors: each must call ``notify_user_signed_up`` itself.
DOORS = {
    "otp/views.py::AuthViewSet.email_verify",
    "otp/views.py::AuthViewSet.phone_verify",
    "otp/views.py::AuthViewSet._resolve_oauth_user",
    "password/views.py::PasswordViewSet.register",
}

#: Doors whose emit lives in the calling view, which holds the request.
EMITTED_BY_CALLER = {
    "password/services.py::PasswordService.change_via_otp":
        "password/views.py::PasswordViewSet.change_otp_verify",
}

#: Account-creating code that is not a self-serve sign-up, and why.
NOT_SELF_SERVE = {
    "otp/views.py::AuthViewSet.anonymous": "guest enrolment",
    "functions.py::provision_user": "org provisioning",
    "login_grant/services.py::LoginGrantService.exchange": "invitation grant",
    "sso_service.py::SSOUserService._provision": "enterprise SSO",
    "admin/views.py::AdminUserViewSet.create_user": "staff-created",
}


def _is_user_receiver(node):
    if isinstance(node, ast.Name):
        return node.id in _USER_NAMES
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "get_user_model"
    )


def _callee(call_node):
    f = call_node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        return f.attr
    return None


def _makes_an_account(call_node):
    f = call_node.func
    if _callee(call_node) == "promote_anonymous_session":
        return True
    if not isinstance(f, ast.Attribute):
        return False
    if f.attr == "create_anonymous_user" and _is_user_receiver(f.value):
        return True
    return (
        f.attr in _CREATE
        and isinstance(f.value, ast.Attribute)
        and f.value.attr == "objects"
        and _is_user_receiver(f.value.value)
    )


def _functions():
    """``{"path::Qual.name": ast node}`` for every function in the package."""
    root = Path(stapel_auth.__file__).parent
    found = {}
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if rel.parts[0] in {"tests", "migrations", "build"} or any(
            p.startswith(".") for p in rel.parts
        ):
            continue

        def walk(node, prefix):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.ClassDef):
                    walk(child, f"{prefix}{child.name}.")
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    found[f"{rel.as_posix()}::{prefix}{child.name}"] = child
                else:
                    walk(child, prefix)

        walk(ast.parse(path.read_text()), "")
    return found


def _calls(fn, predicate):
    return any(isinstance(n, ast.Call) and predicate(n) for n in ast.walk(fn))


def _emits(fn):
    return _calls(fn, lambda n: _callee(n) == "notify_user_signed_up")


class TestDoorInventory:
    def test_every_account_making_function_is_classified(self):
        functions = _functions()
        makers = {name for name, fn in functions.items() if _calls(fn, _makes_an_account)}
        classified = DOORS | set(EMITTED_BY_CALLER) | set(NOT_SELF_SERVE)
        assert makers - classified == set(), (
            "new account-making code: emit user.signed_up there (DOORS) or "
            "list it in NOT_SELF_SERVE with the reason"
        )
        assert classified - makers == set(), "stale inventory entries"

    def test_every_door_emits(self):
        functions = _functions()
        for name in DOORS:
            assert _emits(functions[name]), f"{name} does not emit user.signed_up"
        for name, caller in EMITTED_BY_CALLER.items():
            assert _emits(functions[caller]), f"{caller} does not emit for {name}"

    def test_no_excluded_site_emits(self):
        functions = _functions()
        for name in NOT_SELF_SERVE:
            assert not _emits(functions[name]), f"{name} is not a sign-up"
