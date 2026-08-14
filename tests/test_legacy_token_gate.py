"""The legacy ``POST /token/`` obeys the same gates as ``/password/login/``.

The defect (audit 2026-08-11, P0): ``/token/`` is a password-for-session
trade, but it was registered with an EMPTY gate tuple (``_gate`` reads an
empty tuple as "always on") and its view consulted no setting at all. Three
deployment answers were silently voided:

* ``AUTH_PASSWORD_LOGIN`` — ``False`` on stock defaults. ``/password/login/``
  refuses while it is off; ``/token/`` served the very same credential trade,
  so a deployment that never turned password login on had it fully open;
* ``PASSWORD_LOGIN_STEP_UP`` — ``True`` on stock defaults.
  ``/password/login/`` mints a TOTP challenge; ``/token/`` minted the session
  outright, which is an MFA bypass for every TOTP-enabled account;
* ``LockoutService`` — ``/password/login/`` counts failures and locks the
  identifier; ``/token/`` had no counter, no throttle and no captcha, i.e. an
  unlimited password-guessing oracle.

``tests/test_legacy_token_credentials.py`` enumerates the password→session
routes, but every class there turns ``AUTH_PASSWORD_LOGIN`` on, so the
gate-OFF case had no coverage anywhere. That is the hole this file fills.
"""
import uuid

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_auth.models import UserSession

User = get_user_model()

_PW = "legacy-gate-pass-9"

#: Both switches on — the only configuration in which the endpoint answers.
_OPEN = {"AUTH_PASSWORD_LOGIN": True, "AUTH_LEGACY_TOKEN_LOGIN": True}


def _user(**kw):
    d = dict(
        email=f"lgate-{uuid.uuid4().hex[:10]}@example.com",
        username=f"lgate_{uuid.uuid4().hex[:10]}",
        password=_PW,
        is_email_verified=True,
        auth_type="email",
    )
    d.update(kw)
    return User.objects.create_user(**d)


def _enroll_totp(user):
    import pyotp

    from stapel_auth.mfa.services import TOTPService

    setup = TOTPService.setup(user)
    TOTPService.confirm(user, pyotp.TOTP(setup["secret"]).now())


class _TokenEndpointCase(APITestCase):
    """Shared setup: a real account and a clean lockout cache."""

    def setUp(self):
        cache.clear()
        self.user = _user()

    def _obtain(self, password=_PW, login=None):
        return self.client.post(
            reverse("token_obtain_pair"),
            {"username": login or self.user.username, "password": password},
            format="json",
        )


@override_settings(URL_PREFIX="")
class LegacyTokenIsClosedByDefaultTests(_TokenEndpointCase):
    """Stock defaults must not trade a password for a session here."""

    def test_correct_credentials_are_refused_on_stock_defaults(self):
        resp = self._obtain()
        self.assertEqual(resp.status_code, 403, resp.content)
        self.assertNotIn("access", resp.data)
        self.assertEqual(UserSession.objects.filter(user=self.user).count(), 0)
        self.assertEqual(resp.cookies, {}, "a refusal set a session cookie")

    @override_settings(STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True})
    def test_password_login_alone_does_not_open_the_legacy_alias(self):
        """The alias needs its own explicit switch, not password login's.

        A deployment that wants password login gets ``/password/login/``; the
        deprecated shape is a separate, deliberate act.
        """
        resp = self._obtain()
        self.assertEqual(resp.status_code, 403, resp.content)
        self.assertEqual(UserSession.objects.filter(user=self.user).count(), 0)

    @override_settings(STAPEL_AUTH={"AUTH_LEGACY_TOKEN_LOGIN": True})
    def test_the_alias_is_still_shut_while_password_login_is_off(self):
        """AUTH_PASSWORD_LOGIN=False means no password buys a session — anywhere."""
        resp = self._obtain()
        self.assertEqual(resp.status_code, 403, resp.content)
        self.assertEqual(UserSession.objects.filter(user=self.user).count(), 0)

    @override_settings(STAPEL_AUTH=_OPEN)
    def test_both_switches_on_issues_a_tracked_session(self):
        """The other half of the gate: opening it deliberately still works."""
        resp = self._obtain()
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertTrue(resp.data["access"])
        self.assertEqual(UserSession.objects.filter(user=self.user).count(), 1)


@override_settings(URL_PREFIX="", STAPEL_AUTH=_OPEN)
class LegacyTokenStepUpTests(_TokenEndpointCase):
    """PASSWORD_LOGIN_STEP_UP governs this door too (MFA bypass, P0)."""

    def setUp(self):
        super().setUp()
        _enroll_totp(self.user)

    def test_a_totp_account_gets_a_challenge_not_a_session(self):
        resp = self._obtain()
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertEqual(resp.data["status"], "TOTP_REQUIRED")
        self.assertTrue(resp.data["challenge_token"])
        self.assertNotIn("access", resp.data)
        self.assertEqual(
            UserSession.objects.filter(user=self.user).count(),
            0,
            "the step-up minted a session before the second factor",
        )
        self.assertEqual(resp.cookies, {}, "a challenge set a session cookie")

    @override_settings(STAPEL_AUTH={**_OPEN, "PASSWORD_LOGIN_STEP_UP": False})
    def test_the_step_up_can_be_switched_off_explicitly(self):
        resp = self._obtain()
        self.assertEqual(resp.status_code, 200, resp.content)
        self.assertTrue(resp.data["access"])


@override_settings(URL_PREFIX="", STAPEL_AUTH=_OPEN)
class LegacyTokenLockoutTests(_TokenEndpointCase):
    """The failure counter is shared with /password/login/, not absent."""

    def test_repeated_wrong_passwords_lock_the_endpoint(self):
        for _ in range(4):
            self.assertEqual(self._obtain(password="wrong-one").status_code, 401)
        # The 5th failure crosses LockoutService's first threshold ...
        self.assertEqual(self._obtain(password="wrong-one").status_code, 423)
        # ... and from here even the RIGHT password is refused.
        locked = self._obtain()
        self.assertEqual(locked.status_code, 423, locked.content)
        self.assertEqual(UserSession.objects.filter(user=self.user).count(), 0)

    def test_a_lockout_earned_on_the_dedicated_path_is_honored_here(self):
        """One identifier, one counter — an attacker cannot alternate doors."""
        for _ in range(5):
            self.client.post(
                reverse("password_login"),
                {"login": self.user.username, "password": "wrong-one"},
                format="json",
            )
        resp = self._obtain()
        self.assertEqual(resp.status_code, 423, resp.content)

    def test_a_successful_login_clears_the_counter(self):
        for _ in range(3):
            self.assertEqual(self._obtain(password="wrong-one").status_code, 401)
        self.assertEqual(self._obtain().status_code, 200)
        for _ in range(4):
            self.assertEqual(self._obtain(password="wrong-one").status_code, 401)
        # Without the clear, attempt 4 after the success would already be the
        # 7th in the window and the account would be locked.
        self.assertEqual(self._obtain().status_code, 200)


class LegacyTokenUrlGateTests(TestCase):
    """The route declares its gate in the registry, not an empty tuple."""

    def test_the_route_declares_the_legacy_switch_as_its_gate(self):
        from stapel_auth.urls import GATE_REGISTRY

        entry = GATE_REGISTRY["legacy_token"]
        self.assertEqual(entry.flags, ("AUTH_LEGACY_TOKEN_LOGIN",))
        self.assertEqual([p.name for p in entry.patterns], ["token_obtain_pair"])

    def test_a_host_assembling_its_own_urlconf_gets_no_token_route(self):
        from stapel_auth.urls import get_sessions_urls

        names = [p.name for p in get_sessions_urls()]
        self.assertNotIn("token_obtain_pair", names)
        # ... while the session plumbing on the same factory stays mounted.
        self.assertIn("token_refresh", names)
        self.assertIn("sessions", names)

    @override_settings(STAPEL_AUTH={"AUTH_LEGACY_TOKEN_LOGIN": True})
    def test_the_switch_mounts_the_route_back(self):
        from stapel_auth.urls import get_sessions_urls

        self.assertIn("token_obtain_pair", [p.name for p in get_sessions_urls()])
