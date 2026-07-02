"""Step-up verification: factors, endpoints, flows, and the reference cycle.

Covers the stapel-auth side of stapel_core.verification (see
flows-and-verification.md §2 and the auth.step_up_verification flow):

- factor registration and per-user availability filtering;
- the /verification/{challenge_id}/ endpoint matrix (info / initiate /
  complete × ownership / expiry / wrong factor / lockout);
- a protected demo view end to end: 403 envelope → complete otp_email →
  retry passes (server-side grant and X-Verification-Token header paths);
- OAuth login/callback without forced TOTP (and with OAUTH_STEP_UP=True);
- password login TOTP gated by PASSWORD_LOGIN_STEP_UP;
- flow registration + check_flows for the new endpoints.
"""
import sys
import types
import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import path, reverse
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.test import APITestCase
from rest_framework.views import APIView

from stapel_core.verification import (
    create_challenge,
    factor_registry,
    has_grant,
    requires_verification,
)
from stapel_core.verification.grants import (
    CHALLENGE_KEY,
    get_challenge,
    revoke_grants,
)

User = get_user_model()


def _make_user(**kwargs):
    defaults = dict(
        email=f"verif-{uuid.uuid4().hex[:10]}@example.com",
        username=f"verif_{uuid.uuid4().hex[:10]}",
        password="testpass123",
        is_email_verified=True,
    )
    defaults.update(kwargs)
    return User.objects.create_user(**defaults)


def _bearer(client, user):
    from stapel_core.django.jwt.provider import jwt_provider

    access, _ = jwt_provider.create_tokens(user)
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return access


def _enroll_totp(user):
    import pyotp

    from stapel_auth.mfa.services import TOTPService

    setup = TOTPService.setup(user)
    TOTPService.confirm(user, pyotp.TOTP(setup["secret"]).now())
    return setup["secret"]


# ─────────────────────────────────────────────────────────────────────────────
# Demo protected view + test-only URLConf (root URLConf in tests is
# stapel_auth.urls; the demo endpoint is appended in a synthetic module).
# ─────────────────────────────────────────────────────────────────────────────


class _PayoutDemoView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @requires_verification(
        scope="payout_demo", factors=["otp_email", "totp"], max_age=300
    )
    def post(self, request):
        return Response({"ok": True})


_TEST_URLCONF = "_stapel_auth_verification_test_urls"
_urlconf_module = types.ModuleType(_TEST_URLCONF)
import stapel_auth.urls as _auth_urls  # noqa: E402

_urlconf_module.urlpatterns = list(_auth_urls.urlpatterns) + [
    path("payout-demo/", _PayoutDemoView.as_view()),
]
sys.modules[_TEST_URLCONF] = _urlconf_module


# ─────────────────────────────────────────────────────────────────────────────
# Factor registration and availability
# ─────────────────────────────────────────────────────────────────────────────


class FactorRegistrationTests(TestCase):
    def test_all_four_factors_registered_in_ready(self):
        names = factor_registry.names()
        for factor_id in ("otp_email", "otp_phone", "totp", "passkey"):
            self.assertIn(factor_id, names)

    def test_availability_email_only_user(self):
        user = _make_user()
        available = factor_registry.available_for(
            user, ["otp_email", "otp_phone", "totp", "passkey"]
        )
        self.assertEqual(available, ["otp_email"])

    def test_availability_unverified_email_excluded(self):
        user = _make_user(is_email_verified=False)
        self.assertEqual(
            factor_registry.available_for(user, ["otp_email", "totp"]), []
        )

    def test_availability_verified_phone(self):
        user = _make_user(phone="+12025550142", is_phone_verified=True)
        available = factor_registry.available_for(
            user, ["otp_email", "otp_phone", "totp", "passkey"]
        )
        self.assertEqual(available, ["otp_email", "otp_phone"])

    def test_availability_totp_enrolled(self):
        user = _make_user()
        _enroll_totp(user)
        available = factor_registry.available_for(user, ["totp", "passkey"])
        self.assertEqual(available, ["totp"])

    def test_availability_passkey_registered(self):
        from stapel_auth.models import PasskeyCredential

        user = _make_user()
        PasskeyCredential.objects.create(
            user=user,
            credential_id=uuid.uuid4().bytes,
            public_key=b"test-public-key",
            device_name="Test key",
        )
        self.assertEqual(
            factor_registry.available_for(user, ["passkey"]), ["passkey"]
        )
        # An inactive passkey does not count.
        PasskeyCredential.objects.filter(user=user).update(is_active=False)
        self.assertEqual(factor_registry.available_for(user, ["passkey"]), [])


# ─────────────────────────────────────────────────────────────────────────────
# Endpoint matrix: info / initiate / complete
# ─────────────────────────────────────────────────────────────────────────────


class VerificationEndpointTestBase(APITestCase):
    scope = "endpoint_test"
    factors = ["otp_email", "otp_phone", "totp", "passkey"]

    def setUp(self):
        cache.clear()
        self.user = _make_user()
        _bearer(self.client, self.user)
        self.challenge = create_challenge(self.user, self.scope, self.factors, 300)
        self.challenge_id = self.challenge["challenge_id"]

    def _url(self, name, challenge_id=None):
        return reverse(name, kwargs={"challenge_id": challenge_id or self.challenge_id})

    def _expire_challenge(self):
        cache.delete(CHALLENGE_KEY.format(challenge_id=self.challenge_id))


class ChallengeInfoTests(VerificationEndpointTestBase):
    def test_info_returns_challenge_with_available_factors(self):
        resp = self.client.get(self._url("verification_info"))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["challenge_id"], self.challenge_id)
        self.assertEqual(resp.data["scope"], self.scope)
        # Email-only user: the factor list is filtered to what they can use.
        self.assertEqual(resp.data["factors"], ["otp_email"])
        self.assertEqual(resp.data["expires_at"], self.challenge["expires_at"])

    def test_info_unknown_challenge_404(self):
        resp = self.client.get(self._url("verification_info", "chg_does-not-exist"))
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(
            resp.data["localizable_error"],
            "error.404.verification_challenge_not_found",
        )

    def test_info_expired_challenge_404(self):
        self._expire_challenge()
        resp = self.client.get(self._url("verification_info"))
        self.assertEqual(resp.status_code, 404)

    def test_info_foreign_challenge_404(self):
        _bearer(self.client, _make_user())
        resp = self.client.get(self._url("verification_info"))
        self.assertEqual(resp.status_code, 404)

    def test_info_requires_authentication(self):
        self.client.credentials()
        resp = self.client.get(self._url("verification_info"))
        self.assertIn(resp.status_code, (401, 403))


class ChallengeInitiateTests(VerificationEndpointTestBase):
    def test_initiate_otp_email_returns_masked_target(self):
        resp = self.client.post(
            self._url("verification_initiate"), {"factor": "otp_email"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["factor"], "otp_email")
        target = resp.data["data"]["target"]
        self.assertNotEqual(target, self.user.email)
        self.assertIn("*", target)
        # The OTP record was actually created for the user's email.
        from stapel_auth.models import EmailVerification

        self.assertTrue(
            EmailVerification.objects.filter(email=self.user.email).exists()
        )

    def test_initiate_factor_not_in_challenge_400(self):
        # totp is not enrolled → it is not in the challenge's factor list.
        resp = self.client.post(
            self._url("verification_initiate"), {"factor": "totp"}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(
            resp.data["localizable_error"], "error.400.verification_invalid_factor"
        )

    def test_initiate_unknown_factor_400(self):
        resp = self.client.post(
            self._url("verification_initiate"), {"factor": "carrier_pigeon"}
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(
            resp.data["localizable_error"], "error.400.verification_invalid_factor"
        )

    def test_initiate_missing_factor_field_400(self):
        resp = self.client.post(self._url("verification_initiate"), {})
        self.assertEqual(resp.status_code, 400)

    def test_initiate_unknown_challenge_404(self):
        resp = self.client.post(
            self._url("verification_initiate", "chg_nope"), {"factor": "otp_email"}
        )
        self.assertEqual(resp.status_code, 404)

    def test_initiate_foreign_challenge_404(self):
        _bearer(self.client, _make_user())
        resp = self.client.post(
            self._url("verification_initiate"), {"factor": "otp_email"}
        )
        self.assertEqual(resp.status_code, 404)

    def test_initiate_rate_limited_send_maps_to_400(self):
        first = self.client.post(
            self._url("verification_initiate"), {"factor": "otp_email"}
        )
        self.assertEqual(first.status_code, 200)
        # Second send within the service's 30s window → rate limit error
        # inside the factor → 400 verification_failed.
        second = self.client.post(
            self._url("verification_initiate"), {"factor": "otp_email"}
        )
        self.assertEqual(second.status_code, 400)
        self.assertEqual(
            second.data["localizable_error"], "error.400.verification_failed"
        )

    def test_initiate_passkey_returns_webauthn_options(self):
        from stapel_auth.models import PasskeyCredential

        PasskeyCredential.objects.create(
            user=self.user,
            credential_id=uuid.uuid4().bytes,
            public_key=b"test-public-key",
            device_name="Test key",
        )
        # New challenge so the passkey factor is included.
        challenge = create_challenge(self.user, self.scope, ["passkey"], 300)
        resp = self.client.post(
            self._url("verification_initiate", challenge["challenge_id"]),
            {"factor": "passkey"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("session_key", resp.data["data"])
        self.assertIn("challenge", resp.data["data"]["options"])


class ChallengeCompleteTests(VerificationEndpointTestBase):
    def _initiate_email(self):
        resp = self.client.post(
            self._url("verification_initiate"), {"factor": "otp_email"}
        )
        self.assertEqual(resp.status_code, 200)

    def test_complete_with_correct_code_returns_token_and_grant(self):
        self._initiate_email()
        resp = self.client.post(
            self._url("verification_complete"),
            {"factor": "otp_email", "code": "0000"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIs(resp.data["verified"], True)
        self.assertTrue(resp.data["verification_token"].startswith("vt_"))
        # Server-side grant exists, challenge is consumed.
        self.assertTrue(has_grant(self.user, self.scope))
        self.assertIsNone(get_challenge(self.challenge_id))

    def test_complete_with_wrong_code_400(self):
        self._initiate_email()
        resp = self.client.post(
            self._url("verification_complete"),
            {"factor": "otp_email", "code": "9999"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(
            resp.data["localizable_error"], "error.400.verification_failed"
        )
        self.assertFalse(has_grant(self.user, self.scope))
        # The challenge survives and records the attempt.
        self.assertEqual(get_challenge(self.challenge_id)["attempts"], 1)

    def test_complete_lockout_after_max_attempts(self):
        self._initiate_email()
        for _ in range(4):
            resp = self.client.post(
                self._url("verification_complete"),
                {"factor": "otp_email", "code": "9999"},
            )
            self.assertEqual(resp.status_code, 400)
        # 5th failure (STAPEL_VERIFICATION MAX_ATTEMPTS default) burns the
        # challenge: 423, and the challenge is gone.
        resp = self.client.post(
            self._url("verification_complete"),
            {"factor": "otp_email", "code": "9999"},
        )
        self.assertEqual(resp.status_code, 423)
        self.assertEqual(
            resp.data["localizable_error"], "error.423.verification_locked"
        )
        self.assertIsNone(get_challenge(self.challenge_id))
        # Even the correct code is now a 404 — the client must restart.
        resp = self.client.post(
            self._url("verification_complete"),
            {"factor": "otp_email", "code": "0000"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_complete_wrong_factor_400_without_burning_attempts(self):
        resp = self.client.post(
            self._url("verification_complete"),
            {"factor": "totp", "code": "123456"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(
            resp.data["localizable_error"], "error.400.verification_invalid_factor"
        )
        self.assertEqual(get_challenge(self.challenge_id).get("attempts", 0), 0)

    def test_complete_unknown_challenge_404(self):
        resp = self.client.post(
            self._url("verification_complete", "chg_nope"),
            {"factor": "otp_email", "code": "0000"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_complete_foreign_challenge_404(self):
        _bearer(self.client, _make_user())
        resp = self.client.post(
            self._url("verification_complete"),
            {"factor": "otp_email", "code": "0000"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_complete_with_totp_code(self):
        secret = _enroll_totp(self.user)
        challenge = create_challenge(self.user, self.scope, ["totp"], 300)
        import pyotp

        resp = self.client.post(
            self._url("verification_complete", challenge["challenge_id"]),
            {"factor": "totp", "code": pyotp.TOTP(secret).now()},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertIs(resp.data["verified"], True)


# ─────────────────────────────────────────────────────────────────────────────
# Protected demo view — end to end
# ─────────────────────────────────────────────────────────────────────────────


@override_settings(ROOT_URLCONF=_TEST_URLCONF)
class ProtectedViewEndToEndTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user()
        _bearer(self.client, self.user)

    def _envelope(self):
        resp = self.client.post("/payout-demo/", {})
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(
            resp.data["localizable_error"], "error.403.verification_required"
        )
        verification = resp.data["verification"]
        self.assertEqual(verification["scope"], "payout_demo")
        # totp is listed by the view but the user has none — filtered out.
        self.assertEqual(verification["factors"], ["otp_email"])
        self.assertIn("expires_at", verification)
        return verification["challenge_id"]

    def _complete_email(self, challenge_id, code="0000"):
        return self.client.post(
            reverse("verification_complete", kwargs={"challenge_id": challenge_id}),
            {"factor": "otp_email", "code": code},
        )

    def test_full_cycle_with_server_side_grant(self):
        challenge_id = self._envelope()

        info = self.client.get(
            reverse("verification_info", kwargs={"challenge_id": challenge_id})
        )
        self.assertEqual(info.status_code, 200)
        self.assertEqual(info.data["factors"], ["otp_email"])

        initiate = self.client.post(
            reverse("verification_initiate", kwargs={"challenge_id": challenge_id}),
            {"factor": "otp_email"},
        )
        self.assertEqual(initiate.status_code, 200)

        complete = self._complete_email(challenge_id)
        self.assertEqual(complete.status_code, 200)
        self.assertIs(complete.data["verified"], True)

        # Retry the original request: the grant lives server-side.
        retry = self.client.post("/payout-demo/", {})
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.data, {"ok": True})

    @override_settings(USE_MOCK_EMAIL_OTP=False)
    def test_full_cycle_with_real_code_and_mocked_send(self):
        challenge_id = self._envelope()
        with patch(
            "stapel_core.notifications.request_notification", return_value=True
        ) as mock_send:
            initiate = self.client.post(
                reverse(
                    "verification_initiate", kwargs={"challenge_id": challenge_id}
                ),
                {"factor": "otp_email"},
            )
        self.assertEqual(initiate.status_code, 200)
        self.assertTrue(mock_send.called)
        self.assertEqual(mock_send.call_args.kwargs["email"], self.user.email)

        from stapel_auth.models import EmailVerification

        code = (
            EmailVerification.objects.filter(email=self.user.email)
            .latest("created_at")
            .code
        )
        complete = self._complete_email(challenge_id, code=code)
        self.assertEqual(complete.status_code, 200)
        self.assertEqual(self.client.post("/payout-demo/", {}).status_code, 200)

    def test_stateless_token_header_path(self):
        challenge_id = self._envelope()
        self.client.post(
            reverse("verification_initiate", kwargs={"challenge_id": challenge_id}),
            {"factor": "otp_email"},
        )
        complete = self._complete_email(challenge_id)
        token = complete.data["verification_token"]

        # Simulate a stateless deployment: drop the server-side grant.
        revoke_grants(str(self.user.pk), ["payout_demo"])
        without_header = self.client.post("/payout-demo/", {})
        self.assertEqual(without_header.status_code, 403)

        with_header = self.client.post(
            "/payout-demo/", {}, HTTP_X_VERIFICATION_TOKEN=token
        )
        self.assertEqual(with_header.status_code, 200)

    def test_token_is_user_bound(self):
        challenge_id = self._envelope()
        self.client.post(
            reverse("verification_initiate", kwargs={"challenge_id": challenge_id}),
            {"factor": "otp_email"},
        )
        token = self._complete_email(challenge_id).data["verification_token"]

        other = _make_user()
        _bearer(self.client, other)
        resp = self.client.post(
            "/payout-demo/", {}, HTTP_X_VERIFICATION_TOKEN=token
        )
        self.assertEqual(resp.status_code, 403)


# ─────────────────────────────────────────────────────────────────────────────
# OAuth: no forced TOTP by default; OAUTH_STEP_UP=True restores it
# ─────────────────────────────────────────────────────────────────────────────


class OAuthStepUpTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = _make_user(
            oauth_provider="google", oauth_id=f"g-{uuid.uuid4().hex[:8]}"
        )
        _enroll_totp(self.user)

    def _oauth_user_data(self):
        from stapel_auth.oauth_providers import OAuthUserData

        return OAuthUserData(
            id=self.user.oauth_id,
            email=self.user.email,
            username=self.user.username,
            avatar=None,
        )

    def test_oauth_login_totp_user_gets_tokens_by_default(self):
        with patch(
            "stapel_auth.services.OAuthService.get_user_data",
            return_value=self._oauth_user_data(),
        ):
            resp = self.client.post(
                reverse("oauth_login"),
                {"provider": "google", "access_token": "fake"},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertIn("tokens", resp.data)
        self.assertEqual(resp.data["status"], "LOGGED_IN")

    @override_settings(OAUTH_STEP_UP=True)
    def test_oauth_login_totp_challenge_with_step_up_enabled(self):
        with patch(
            "stapel_auth.services.OAuthService.get_user_data",
            return_value=self._oauth_user_data(),
        ):
            resp = self.client.post(
                reverse("oauth_login"),
                {"provider": "google", "access_token": "fake"},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "TOTP_REQUIRED")
        self.assertIn("challenge_token", resp.data)
        self.assertNotIn("tokens", resp.data)

    @override_settings(OAUTH_STEP_UP=True)
    def test_oauth_login_without_totp_unaffected_by_step_up(self):
        from stapel_auth.mfa.services import TOTPService

        TOTPService.force_disable(self.user)
        with patch(
            "stapel_auth.services.OAuthService.get_user_data",
            return_value=self._oauth_user_data(),
        ):
            resp = self.client.post(
                reverse("oauth_login"),
                {"provider": "google", "access_token": "fake"},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "LOGGED_IN")


# ─────────────────────────────────────────────────────────────────────────────
# Password login: TOTP branch gated by PASSWORD_LOGIN_STEP_UP (default True)
# ─────────────────────────────────────────────────────────────────────────────


@override_settings(STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True})
class PasswordLoginStepUpTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.password = "s3cure-pass-123"
        self.user = _make_user(password=self.password)
        _enroll_totp(self.user)

    def _login(self):
        return self.client.post(
            reverse("password_login"),
            {"login": self.user.email, "password": self.password},
        )

    def test_default_keeps_totp_challenge(self):
        resp = self._login()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "TOTP_REQUIRED")
        self.assertIn("challenge_token", resp.data)

    @override_settings(
        STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True, "PASSWORD_LOGIN_STEP_UP": False}
    )
    def test_disabled_gate_issues_tokens_directly(self):
        resp = self._login()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "LOGGED_IN")
        self.assertIn("tokens", resp.data)


# ─────────────────────────────────────────────────────────────────────────────
# Flows: registration + check_flows over the URLConf
# ─────────────────────────────────────────────────────────────────────────────

# Legacy endpoints predating the flow engine — exempted from coverage the
# same way a CI run would pass them via `check_flows --allow ...`. The new
# verification endpoints are deliberately NOT here: they must be covered by
# the auth.step_up_verification flow.
LEGACY_FLOW_ALLOWLIST = (
    "/token",
    "/sessions",
    "/phone",
    "/anonymous/",
    "/me/",
    "/logout/",
    "/verify/",
    "/email/change/",
    "/oauth",
    "service-keys",
    "drf_format_suffix",
    "/capabilities/",
    "/admin-users/",
    "/password/methods",
    "/password/change",
    "/password/reset",
    "/password/register",
    "/qr/",
    "/security/",
    "/totp/",
    "/passkey",
    "/magic/",
    "/sso/",
    "/.well-known/",
)


class FlowDocumentationTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        from stapel_core.flows import autodiscover_flows

        autodiscover_flows()

    def test_flows_registered_with_steps(self):
        from stapel_core.flows import flow_registry

        ids = [f.id for f in flow_registry.all()]
        self.assertIn("auth.passwordless_login", ids)
        self.assertIn("auth.password_login", ids)
        self.assertIn("auth.step_up_verification", ids)

        step_up = flow_registry.get("auth.step_up_verification")
        kinds = [s.kind for s in step_up.sorted_steps()]
        self.assertEqual(kinds, ["human", "http", "http", "http", "human"])

        passwordless = flow_registry.get("auth.passwordless_login")
        self.assertIn("action", [s.kind for s in passwordless.steps])

    def test_flow_step_annotations_on_view_methods(self):
        from stapel_core.flows.registry import FLOWS_ATTR

        from stapel_auth.otp.views import AuthViewSet
        from stapel_auth.password.views import PasswordViewSet
        from stapel_auth.verification.views import VerificationViewSet

        for handler, flow_id in (
            (AuthViewSet.email_request, "auth.passwordless_login"),
            (AuthViewSet.email_verify, "auth.passwordless_login"),
            (PasswordViewSet.login, "auth.password_login"),
            (VerificationViewSet.info, "auth.step_up_verification"),
            (VerificationViewSet.initiate, "auth.step_up_verification"),
            (VerificationViewSet.complete, "auth.step_up_verification"),
        ):
            memberships = getattr(handler, FLOWS_ATTR, [])
            self.assertIn(flow_id, [m["flow"] for m in memberships], handler)

    def test_check_flows_passes_with_legacy_allowlist(self):
        from stapel_core.flows.checks import check_flows

        issues = check_flows(extra_allowlist=LEGACY_FLOW_ALLOWLIST)
        errors = [i for i in issues if i.level == "error"]
        # The DRF DefaultRouter's auto-generated API root has the literal
        # path "/" which no substring allowlist can target without matching
        # everything — it is machinery, not an API endpoint.
        errors = [e for e in errors if "APIRootView" not in e.message]
        self.assertEqual([e.message for e in errors], [])

    def test_verification_endpoints_not_swallowed_by_allowlist(self):
        # Guard the previous test's meaning: no allowlist entry matches the
        # verification endpoints, so check_flows really did verify their
        # flow coverage.
        for suffix in ("", "initiate/", "complete/"):
            path_ = f"/verification/<str:challenge_id>/{suffix}"
            for sub in LEGACY_FLOW_ALLOWLIST:
                self.assertNotIn(sub, path_)

    def test_verification_contract_visible_on_demo_view(self):
        from stapel_core.verification.decorators import view_verification_contract

        contract = view_verification_contract(_PayoutDemoView)
        self.assertEqual(contract["scope"], "payout_demo")
        self.assertEqual(contract["factors"], ["otp_email", "totp"])
