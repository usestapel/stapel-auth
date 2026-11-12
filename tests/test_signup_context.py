"""``signup_context``: an opaque object carried from every sign-up door into ``user.signed_up``.

One test per door (fresh and promoted where the door has both), the OAuth
redirect flow through its state, the bounds refusing at the HTTP edge, and
the doors' inventory kept honest: every call of ``notify_user_signed_up``
from a door passes the context on.
"""
import ast
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
from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.errors import ERR_400_SIGNUP_CONTEXT_INVALID
from stapel_auth.oauth_providers import OAuthUserData
from stapel_auth.signup_context import MAX_BYTES, MAX_KEYS, parse_signup_context

User = get_user_model()

PASSWORD_ON = {"AUTH_PASSWORD_REGISTRATION": True}
CONTEXT = {"referral_code": "FRIEND-42", "captured_at": "2026-11-12T10:00:00Z", "n": 3, "ok": True, "x": None}


def _signed_up(user_id):
    return [
        json.loads(row.event_json)["payload"]
        for row in OutboxEvent.objects.filter(topic="user.signed_up")
        if json.loads(row.event_json)["payload"]["user_id"] == str(user_id)
    ]


def _bearer(user) -> APIClient:
    from stapel_core.django.jwt.provider import jwt_provider

    access, _ = jwt_provider.create_tokens(user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return client


def _email_verify(client, email, **extra):
    with patch(
        "stapel_auth.otp.services.EmailVerificationService.verify_code",
        return_value={"success": True},
    ):
        return client.post(reverse("email_verify"), {"email": email, "code": "1234", **extra}, format="json")


def _phone_verify(client, phone, **extra):
    with patch(
        "stapel_auth.otp.services.PhoneVerificationService.verify_code",
        return_value={"success": True},
    ):
        return client.post(reverse("phone_verify"), {"phone": phone, "code": "1234", **extra}, format="json")


def _provider_user(uid, email):
    return OAuthUserData(id=uid, email=email, username=uid, avatar=None, email_verified=True)


def _oauth_login(client, uid, email, **extra):
    with patch(
        "stapel_auth.oauth.services.OAuthService.get_user_data",
        return_value=_provider_user(uid, email),
    ) as provider:
        resp = client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "tok", **extra},
            format="json",
        )
    resp.provider_called = provider.called
    return resp


@pytest.fixture(autouse=True)
def _clean():
    cache.clear()


# ── every door copies it verbatim ───────────────────────────────────────────


@pytest.mark.django_db
class TestFreshAccounts:
    def test_email_otp(self):
        resp = _email_verify(APIClient(), "ctx-mail@shop.example", signup_context=CONTEXT)
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(resp.data["user"]["id"])
        assert payload["signup_context"] == CONTEXT

    def test_phone_otp(self):
        resp = _phone_verify(APIClient(), "+12025550311", signup_context=CONTEXT)
        [payload] = _signed_up(resp.data["user"]["id"])
        assert payload["signup_context"] == CONTEXT

    def test_oauth_login(self):
        resp = _oauth_login(APIClient(), "uid-ctx", "ctx-oauth@shop.example", signup_context=CONTEXT)
        [payload] = _signed_up(resp.data["user"]["id"])
        assert payload["signup_context"] == CONTEXT

    @override_settings(STAPEL_AUTH=PASSWORD_ON)
    def test_password_register(self):
        resp = APIClient().post(
            reverse("password_register"),
            {"email": "ctx-pw@shop.example", "password": "brandnew456!", "signup_context": CONTEXT},
            format="json",
        )
        [payload] = _signed_up(resp.data["user"]["id"])
        assert payload["signup_context"] == CONTEXT

    def test_without_one_the_field_is_absent(self):
        resp = _email_verify(APIClient(), "ctx-none@shop.example")
        [payload] = _signed_up(resp.data["user"]["id"])
        assert "signup_context" not in payload

    def test_an_empty_object_is_none(self):
        resp = _email_verify(APIClient(), "ctx-empty@shop.example", signup_context={})
        [payload] = _signed_up(resp.data["user"]["id"])
        assert "signup_context" not in payload

    def test_a_login_carries_nothing(self):
        User.objects.create(email="ctx-known@shop.example", auth_type="email", is_email_verified=True)
        resp = _email_verify(APIClient(), "ctx-known@shop.example", signup_context=CONTEXT)
        assert resp.data["status"] == "LOGGED_IN"
        assert not OutboxEvent.objects.filter(topic="user.signed_up").exists()

    def test_the_payload_still_matches_the_fact_schema(self):
        import jsonschema

        resp = _email_verify(APIClient(), "ctx-shape@shop.example", signup_context=CONTEXT)
        [payload] = _signed_up(resp.data["user"]["id"])
        path = Path(stapel_auth.__file__).parent / "schemas" / "emits" / "user.signed_up.json"
        jsonschema.validate(payload, json.loads(path.read_text()))


@pytest.mark.django_db
class TestPromotedGuests:
    def test_email_otp(self):
        guest = User.create_anonymous_user()
        _email_verify(_bearer(guest), "ctx-gmail@shop.example", signup_context=CONTEXT)
        [payload] = _signed_up(guest.id)
        assert payload["was_guest"] is True and payload["signup_context"] == CONTEXT

    def test_phone_otp(self):
        guest = User.create_anonymous_user()
        _phone_verify(_bearer(guest), "+12025550322", signup_context=CONTEXT)
        [payload] = _signed_up(guest.id)
        assert payload["signup_context"] == CONTEXT

    def test_oauth_login(self):
        guest = User.create_anonymous_user()
        _oauth_login(_bearer(guest), "uid-gctx", "ctx-goauth@shop.example", signup_context=CONTEXT)
        [payload] = _signed_up(guest.id)
        assert payload["signup_context"] == CONTEXT

    @override_settings(STAPEL_AUTH=PASSWORD_ON)
    def test_password_register(self):
        guest = User.create_anonymous_user()
        _bearer(guest).post(
            reverse("password_register"),
            {"email": "ctx-gpw@shop.example", "password": "brandnew456!", "signup_context": CONTEXT},
            format="json",
        )
        [payload] = _signed_up(guest.id)
        assert payload["signup_context"] == CONTEXT

    def test_change_via_otp_promotion(self):
        guest = User.create_anonymous_user()
        guest.email = "ctx-change@shop.example"
        guest.is_email_verified = True
        guest.save()
        with patch(
            "stapel_auth.otp.services.EmailVerificationService.verify_code",
            return_value={"success": True},
        ):
            resp = _bearer(guest).post(
                reverse("password_change_otp_verify"),
                {"method": "email", "code": "1234", "new_password": "brandnew456!", "signup_context": CONTEXT},
                format="json",
            )
        assert resp.data["status"] == "REGISTERED"
        [payload] = _signed_up(guest.id)
        assert payload["signup_context"] == CONTEXT


@pytest.mark.django_db
class TestOAuthRedirectFlow:
    PROVIDERS = {"OAUTH_PROVIDERS": {"google": {"client_id": "cid", "client_secret": "secret"}}}

    def _flow(self, query):
        client = APIClient()
        with override_settings(STAPEL_AUTH=self.PROVIDERS):
            authorize = client.get(reverse("oauth_authorize", kwargs={"provider": "google"}), query)
            assert authorize.status_code == 302
            state = authorize.url.split("state=")[1].split("&")[0]
            assert "FRIEND-42" not in authorize.url
            with patch(
                "stapel_auth.oauth_providers.GoogleProvider.exchange_code", return_value="tok",
            ), patch(
                "stapel_auth.oauth.services.OAuthService.get_user_data",
                return_value=_provider_user("uid-redirect", "ctx-redirect@shop.example"),
            ):
                callback = client.get(
                    reverse("oauth_callback", kwargs={"provider": "google"}),
                    {"code": "authcode", "state": state},
                )
        assert callback.status_code in (200, 302), getattr(callback, "data", None)
        return _signed_up(User.objects.get(email="ctx-redirect@shop.example").id)

    def test_the_context_rides_the_flow_state_to_the_callback(self):
        [payload] = self._flow({"signup_context": json.dumps(CONTEXT)})
        assert payload["signup_context"] == CONTEXT

    @pytest.mark.parametrize("raw", ["not json", json.dumps({"nested": {"a": 1}})])
    def test_a_malformed_one_is_dropped_and_the_sign_in_goes_on(self, raw, caplog):
        with caplog.at_level("WARNING", logger="stapel_auth.signup_context"):
            [payload] = self._flow({"signup_context": raw})
        assert "signup_context" not in payload
        assert "malformed signup_context" in caplog.text


# ── bounds: untrusted input refused at the edge ─────────────────────────────

MALFORMED = [
    pytest.param("FRIEND-42", id="not-an-object"),
    pytest.param(["FRIEND-42"], id="a-list"),
    pytest.param({"ref": {"code": "x"}}, id="nested-object"),
    pytest.param({"ref": ["x"]}, id="list-value"),
    pytest.param({"ref": "x" * 257}, id="long-string"),
    pytest.param({"bad key": "x"}, id="key-with-space"),
    pytest.param({"k" * 65: "x"}, id="long-key"),
    pytest.param({f"k{i}": i for i in range(MAX_KEYS + 1)}, id="too-many-keys"),
    pytest.param({f"k{i}": "v" * 200 for i in range(12)}, id="too-many-bytes"),
    pytest.param({"n": 2**60}, id="unsafe-integer"),
]


@pytest.mark.django_db
class TestRefusals:
    @pytest.mark.parametrize("context", MALFORMED)
    def test_email_otp_refuses_before_creating_anything(self, context):
        resp = _email_verify(APIClient(), "ctx-bad@shop.example", signup_context=context)
        assert resp.status_code == 400, resp.data
        assert resp.data["localizable_error"] == ERR_400_SIGNUP_CONTEXT_INVALID
        assert not User.objects.filter(email="ctx-bad@shop.example").exists()

    def test_phone_otp_refuses(self):
        resp = _phone_verify(APIClient(), "+12025550333", signup_context={"ref": {"x": 1}})
        assert resp.data["localizable_error"] == ERR_400_SIGNUP_CONTEXT_INVALID

    def test_oauth_login_refuses_before_asking_the_provider(self):
        resp = _oauth_login(APIClient(), "uid-bad", "ctx-bad-oauth@shop.example", signup_context=[1])
        assert resp.status_code == 400
        assert resp.data["localizable_error"] == ERR_400_SIGNUP_CONTEXT_INVALID
        assert resp.provider_called is False

    @override_settings(STAPEL_AUTH=PASSWORD_ON)
    def test_password_register_refuses(self):
        resp = APIClient().post(
            reverse("password_register"),
            {"email": "ctx-bad-pw@shop.example", "password": "brandnew456!", "signup_context": "x"},
            format="json",
        )
        assert resp.data["localizable_error"] == ERR_400_SIGNUP_CONTEXT_INVALID
        assert not User.objects.filter(email="ctx-bad-pw@shop.example").exists()

    def test_the_byte_bound_is_on_the_encoded_object(self):
        fits = {f"k{i:02d}": "v" * 100 for i in range(16)}
        assert len(json.dumps(fits, separators=(",", ":"))) <= MAX_BYTES
        assert parse_signup_context(fits) == fits


# ── inventory: every door passes it on ──────────────────────────────────────


def test_every_door_call_passes_the_signup_context():
    from .test_user_signed_up import DOORS, EMITTED_BY_CALLER, _callee, _functions

    functions = _functions()
    doors = set(DOORS) | set(EMITTED_BY_CALLER.values())
    for name in doors:
        calls = [
            n for n in ast.walk(functions[name])
            if isinstance(n, ast.Call) and _callee(n) == "notify_user_signed_up"
        ]
        assert calls, name
        for call_node in calls:
            assert any(k.arg == "signup_context" for k in call_node.keywords), (
                f"{name} emits user.signed_up without passing signup_context"
            )
