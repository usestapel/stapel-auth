"""Legacy /totp/step-up/ deprecation + the server-side grant bridge.

Covers the stapel-auth side of the step-up unification (see
auth-stepup-unification.md): the one-time X-Step-Up-Token surface is
deprecated (Deprecation header, process warning, deprecated OpenAPI flag,
warning-emitting service methods) but keeps working through 0.x, and a
successful call ALSO writes a reusable server-side verification grant
(stapel_core.verification) for LEGACY_STEP_UP_GRANT_SCOPES so already-deployed
legacy frontends keep passing @requires_verification while the backend
migrates its guards.

Negative behaviours asserted: replay (the bridged grant is reusable, unlike
the one-time token), an expired/revoked grant re-challenges, no scope
escalation (a grant is written only for the configured scopes), and no grant
on a wrong code / a user without TOTP.
"""
import sys
import types
import uuid
import warnings

import pyotp
from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import path, reverse
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.test import APITestCase
from rest_framework.views import APIView

from stapel_core.verification import (
    has_grant,
    requires_verification,
)
from stapel_core.verification.grants import revoke_grants

from stapel_auth.mfa.services import TOTPService

User = get_user_model()


def _make_user(**kwargs):
    defaults = dict(
        email=f"su-{uuid.uuid4().hex[:10]}@example.com",
        username=f"su_{uuid.uuid4().hex[:10]}",
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
    setup = TOTPService.setup(user)
    secret = setup["secret"]
    TOTPService.confirm(user, pyotp.TOTP(secret).now())
    return secret


# A protected endpoint on the unified contract, scoped to "sensitive" — the
# default LEGACY_STEP_UP_GRANT_SCOPES scope the bridge grants.
class _SensitiveDemoView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @requires_verification(scope="sensitive", factors=["totp"], max_age=900)
    def post(self, request):
        return Response({"ok": True})


_TEST_URLCONF = "_stapel_auth_stepup_deprecation_test_urls"
_urlconf_module = types.ModuleType(_TEST_URLCONF)
import stapel_auth.urls as _auth_urls  # noqa: E402

_urlconf_module.urlpatterns = list(_auth_urls.urlpatterns) + [
    path("sensitive-demo/", _SensitiveDemoView.as_view()),
]
sys.modules[_TEST_URLCONF] = _urlconf_module


@override_settings(ROOT_URLCONF=_TEST_URLCONF)
class LegacyStepUpEndpointTests(APITestCase):
    def setUp(self):
        self.user = _make_user()
        self.secret = _enroll_totp(self.user)
        _bearer(self.client, self.user)

    def _step_up(self, code=None):
        return self.client.post(
            reverse("totp_step_up"),
            {"code": code if code is not None else pyotp.TOTP(self.secret).now()},
            format="json",
        )

    # ── still functional (issuer) ─────────────────────────────────────────

    def test_valid_code_issues_legacy_token(self):
        resp = self._step_up()
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data["step_up_token"])
        self.assertEqual(resp.data["expires_in"], TOTPService.STEP_UP_TTL)

    def test_wrong_code_rejected(self):
        resp = self._step_up(code="000000")
        self.assertEqual(resp.status_code, 400)

    # ── deprecation surface ───────────────────────────────────────────────

    def test_response_carries_deprecation_headers(self):
        resp = self._step_up()
        self.assertEqual(resp["Deprecation"], "true")
        self.assertIn("successor-version", resp["Link"])

    def test_once_per_process_warning(self):
        # The endpoint logs a single deprecation warning per process.
        import stapel_auth.mfa.views as _views

        _views._LEGACY_STEP_UP_WARNED = False
        with self.assertLogs(_views.logger, level="WARNING") as cm:
            self._step_up()
        self.assertTrue(any("DEPRECATED" in m for m in cm.output))

    # ── the server-side grant bridge ──────────────────────────────────────

    def test_bridge_writes_verification_grant(self):
        self.assertFalse(has_grant(self.user, "sensitive"))
        self._step_up()
        self.assertTrue(has_grant(self.user, "sensitive"))

    def test_bridged_grant_opens_protected_endpoint(self):
        # Before step-up the guarded endpoint challenges with the envelope.
        challenged = self.client.post("/sensitive-demo/", {}, format="json")
        self.assertEqual(challenged.status_code, 403)
        self.assertIn("verification", challenged.data)

        self._step_up()

        # After step-up the same request passes on the server-side grant.
        passed = self.client.post("/sensitive-demo/", {}, format="json")
        self.assertEqual(passed.status_code, 200)

    def test_grant_is_reusable_replay(self):
        # Unlike the one-time X-Step-Up-Token, the bridged grant is reusable
        # within max_age — repeated protected calls all pass.
        self._step_up()
        for _ in range(3):
            resp = self.client.post("/sensitive-demo/", {}, format="json")
            self.assertEqual(resp.status_code, 200)

    def test_expired_grant_re_challenges(self):
        self._step_up()
        self.assertEqual(
            self.client.post("/sensitive-demo/", {}, format="json").status_code, 200
        )
        # Simulate max_age expiry: drop the grant. The endpoint challenges again.
        revoke_grants(str(self.user.pk), ["sensitive"])
        again = self.client.post("/sensitive-demo/", {}, format="json")
        self.assertEqual(again.status_code, 403)
        self.assertIn("verification", again.data)

    def test_no_scope_escalation(self):
        # The bridge grants only the configured scopes — a step-up does not
        # satisfy an unrelated scope (no factor/scope downgrade attack).
        self._step_up()
        self.assertTrue(has_grant(self.user, "sensitive"))
        self.assertFalse(has_grant(self.user, "payout"))

    def test_wrong_code_writes_no_grant(self):
        self._step_up(code="000000")
        self.assertFalse(has_grant(self.user, "sensitive"))

    @override_settings(STAPEL_AUTH={"LEGACY_STEP_UP_GRANT_SCOPES": []})
    def test_bridge_disabled_issues_token_only(self):
        resp = self._step_up()
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data["step_up_token"])
        self.assertFalse(has_grant(self.user, "sensitive"))

    @override_settings(STAPEL_AUTH={"LEGACY_STEP_UP_GRANT_SCOPES": ["a", "b"]})
    def test_bridge_honours_configured_scopes(self):
        self._step_up()
        self.assertTrue(has_grant(self.user, "a"))
        self.assertTrue(has_grant(self.user, "b"))
        self.assertFalse(has_grant(self.user, "sensitive"))


class LegacyStepUpNoTotpTests(APITestCase):
    """A user without an active TOTP device cannot step up (and gets no grant)."""

    def setUp(self):
        self.user = _make_user()
        _bearer(self.client, self.user)

    def test_no_totp_device_rejected_no_grant(self):
        resp = self.client.post(
            reverse("totp_step_up"), {"code": "123456"}, format="json"
        )
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(has_grant(self.user, "sensitive"))


class LegacyStepUpServiceDeprecationTests(APITestCase):
    """The public service methods warn but keep working through 0.x."""

    def setUp(self):
        self.user = _make_user()
        self.secret = _enroll_totp(self.user)

    def test_create_step_up_warns_and_works(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            token = TOTPService.create_step_up(self.user, pyotp.TOTP(self.secret).now())
        self.assertTrue(token)
        self.assertTrue(
            any(issubclass(w.category, DeprecationWarning) for w in caught)
        )

    def test_consume_step_up_warns_and_works(self):
        token = TOTPService._issue_step_up_token(
            self.user, pyotp.TOTP(self.secret).now()
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            ok = TOTPService.consume_step_up(self.user, token)
        self.assertTrue(ok)
        self.assertTrue(
            any(issubclass(w.category, DeprecationWarning) for w in caught)
        )
        # one-time: the token is consumed, a second consume fails
        self.assertFalse(TOTPService.consume_step_up(self.user, token))
