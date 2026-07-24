"""First-login intermediates (org-program §C2): forced password change and
the limited mfa-enroll session.

Covers: both FIRST_LOGIN_REQUIRED intermediates on password login, the
release gate (flag-less logins keep the exact pre-0.12 response shape), the
legacy /token/ endpoint's structured 403s, /password/forced-change/
(happy / invalid token / weak password / chained mfa_enroll), the enroll
exchange (enroll_only claim, no refresh), DenyEnrollOnly's surface cut, the
TOTP step-up interplay, and the full enroll upgrade: activating the strong
factor clears the flag, emits user.mfa_enabled and returns full tokens.
"""
import json
import uuid

from django.contrib.auth import get_user_model
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_core.django.jwt.provider import jwt_provider
from stapel_core.django.outbox.models import OutboxEvent

from stapel_auth.errors import (
    ERR_400_FIRST_LOGIN_CHALLENGE_INVALID,
    ERR_403_MFA_ENROLLMENT_REQUIRED,
    ERR_403_PASSWORD_CHANGE_REQUIRED,
)

User = get_user_model()

_PW = "initial-org-password-1"
_PASSWORD_ON = {"AUTH_PASSWORD_LOGIN": True}


def _make_user(**kw):
    d = dict(
        email=f"{uuid.uuid4().hex[:10]}@example.com",
        username=f"u_{uuid.uuid4().hex[:10]}",
        password=_PW,
    )
    d.update(kw)
    return User.objects.create_user(**d)


def _provisioned(**flags):
    """Org-provisioned-style user: namespaced username, no email anchor."""
    user = User.objects.create(
        username=f"org{uuid.uuid4().hex[:6]}/{uuid.uuid4().hex[:8]}",
        email=None,
        auth_type="login",
        **flags,
    )
    user.set_password(_PW)
    user.save(update_fields=["password"])
    return user


@override_settings(STAPEL_AUTH=_PASSWORD_ON)
class LoginIntermediateTests(APITestCase):
    def _login(self, user):
        return self.client.post(
            reverse("password_login"),
            {"login": user.username, "password": _PW},
            format="json",
        )

    def test_password_change_required_intermediate(self):
        user = _provisioned(password_change_required=True)
        resp = self._login(user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "FIRST_LOGIN_REQUIRED")
        self.assertEqual(resp.data["requires"], "password_change")
        self.assertEqual(resp.data["expires_in"], 600)
        self.assertTrue(resp.data["challenge_token"])
        self.assertNotIn("tokens", resp.data)

    def test_mfa_enroll_required_intermediate(self):
        user = _provisioned(mfa_enrollment_required=True)
        resp = self._login(user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["requires"], "mfa_enroll")

    def test_password_change_wins_when_both_flags(self):
        user = _provisioned(
            password_change_required=True, mfa_enrollment_required=True
        )
        resp = self._login(user)
        self.assertEqual(resp.data["requires"], "password_change")

    def test_unflagged_login_unchanged(self):
        """Release gate: no flags → the pre-0.12 AuthResponse, no new keys."""
        user = _make_user()
        resp = self._login(user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "LOGGED_IN")
        self.assertEqual(set(resp.data), {"status", "user", "tokens"})
        self.assertTrue(resp.data["tokens"]["access"])

    def test_mfa_enroll_self_heals_with_existing_strong_factor(self):
        """Flag up but a strong factor exists → flag cleared, full session."""
        user = _make_user(
            phone="+79991230001", is_phone_verified=True,
            mfa_enrollment_required=True,
        )
        resp = self._login(user)
        self.assertEqual(resp.data["status"], "LOGGED_IN")
        user.refresh_from_db()
        self.assertFalse(user.mfa_enrollment_required)


@override_settings(URL_PREFIX="")
class TokenEndpointFlagTests(APITestCase):
    """The legacy /token/ obtain endpoint cannot run the intermediate dance —
    flagged accounts get the structured 403 instead of a session."""

    def _obtain(self, user):
        return self.client.post(
            reverse("token_obtain_pair"),
            {"username": user.username, "password": _PW},
            format="json",
        )

    def test_password_change_required_403(self):
        user = _provisioned(password_change_required=True)
        resp = self._obtain(user)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.data["localizable_error"], ERR_403_PASSWORD_CHANGE_REQUIRED)

    def test_mfa_enrollment_required_403(self):
        user = _provisioned(mfa_enrollment_required=True)
        resp = self._obtain(user)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(resp.data["localizable_error"], ERR_403_MFA_ENROLLMENT_REQUIRED)

    def test_unflagged_gets_tokens(self):
        user = _make_user()
        resp = self._obtain(user)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("access", resp.data)


@override_settings(STAPEL_AUTH=_PASSWORD_ON)
class ForcedChangeTests(APITestCase):
    def _challenge(self, user):
        resp = self.client.post(
            reverse("password_login"),
            {"login": user.username, "password": _PW},
            format="json",
        )
        assert resp.data["requires"] == "password_change", resp.data
        return resp.data["challenge_token"]

    def test_happy_path(self):
        user = _provisioned(password_change_required=True)
        token = self._challenge(user)
        resp = self.client.post(
            reverse("password_forced_change"),
            {"challenge_token": token, "new_password": "my-very-own-password-7"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "LOGGED_IN")
        self.assertTrue(resp.data["tokens"]["access"])

        user.refresh_from_db()
        self.assertFalse(user.password_change_required)
        self.assertFalse(user.check_password(_PW))
        self.assertTrue(user.check_password("my-very-own-password-7"))

        # Single use: the challenge is burned after success.
        again = self.client.post(
            reverse("password_forced_change"),
            {"challenge_token": token, "new_password": "another-own-password-8"},
            format="json",
        )
        self.assertEqual(again.status_code, 400)
        self.assertEqual(
            again.data["localizable_error"], ERR_400_FIRST_LOGIN_CHALLENGE_INVALID
        )

    def test_invalid_token(self):
        resp = self.client.post(
            reverse("password_forced_change"),
            {"challenge_token": "nope", "new_password": "my-very-own-password-7"},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(
            resp.data["localizable_error"], ERR_400_FIRST_LOGIN_CHALLENGE_INVALID
        )

    @override_settings(
        STAPEL_AUTH=_PASSWORD_ON,
        AUTH_PASSWORD_VALIDATORS=[{
            "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
            "OPTIONS": {"min_length": 12},
        }],
    )
    def test_weak_password_rejected_and_challenge_survives(self):
        user = _provisioned(password_change_required=True)
        token = self._challenge(user)
        weak = self.client.post(
            reverse("password_forced_change"),
            {"challenge_token": token, "new_password": "shortpass"},
            format="json",
        )
        self.assertEqual(weak.status_code, 400)
        user.refresh_from_db()
        self.assertTrue(user.password_change_required)
        self.assertTrue(user.check_password(_PW))

        # The rejected password did NOT burn the challenge — retry succeeds.
        retry = self.client.post(
            reverse("password_forced_change"),
            {"challenge_token": token, "new_password": "long-enough-password-42"},
            format="json",
        )
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.data["status"], "LOGGED_IN")

    def test_chains_into_mfa_enroll_when_both_flags(self):
        user = _provisioned(
            password_change_required=True, mfa_enrollment_required=True
        )
        token = self._challenge(user)
        resp = self.client.post(
            reverse("password_forced_change"),
            {"challenge_token": token, "new_password": "my-very-own-password-7"},
            format="json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "FIRST_LOGIN_REQUIRED")
        self.assertEqual(resp.data["requires"], "mfa_enroll")
        user.refresh_from_db()
        self.assertFalse(user.password_change_required)
        self.assertTrue(user.mfa_enrollment_required)

    def test_wrong_requirement_token_rejected(self):
        """An mfa_enroll challenge cannot be spent on forced-change."""
        user = _provisioned(mfa_enrollment_required=True)
        resp = self.client.post(
            reverse("password_login"),
            {"login": user.username, "password": _PW},
            format="json",
        )
        token = resp.data["challenge_token"]
        forced = self.client.post(
            reverse("password_forced_change"),
            {"challenge_token": token, "new_password": "my-very-own-password-7"},
            format="json",
        )
        self.assertEqual(forced.status_code, 400)


@override_settings(STAPEL_AUTH=_PASSWORD_ON)
class StepUpInterplayTests(APITestCase):
    """A TOTP-enabled flagged account proves the second factor FIRST; the
    first-login intermediate comes from the step-up verify."""

    def test_totp_challenge_then_first_login_intermediate(self):
        import pyotp

        from stapel_auth.models import TOTPDevice

        user = _provisioned(password_change_required=True)
        secret = pyotp.random_base32()
        TOTPDevice.objects.create(user=user, secret=secret, is_active=True)

        login = self.client.post(
            reverse("password_login"),
            {"login": user.username, "password": _PW},
            format="json",
        )
        self.assertEqual(login.data["status"], "TOTP_REQUIRED")

        verify = self.client.post(
            reverse("totp_challenge_verify"),
            {
                "challenge_token": login.data["challenge_token"],
                "code": pyotp.TOTP(secret).now(),
            },
            format="json",
        )
        self.assertEqual(verify.status_code, 200)
        self.assertEqual(verify.data["status"], "FIRST_LOGIN_REQUIRED")
        self.assertEqual(verify.data["requires"], "password_change")


@override_settings(STAPEL_AUTH=_PASSWORD_ON)
class EnrollSessionTests(APITestCase):
    def _enroll_session(self, user):
        login = self.client.post(
            reverse("password_login"),
            {"login": user.username, "password": _PW},
            format="json",
        )
        assert login.data["requires"] == "mfa_enroll", login.data
        resp = self.client.post(
            reverse("mfa_enroll_exchange"),
            {"challenge_token": login.data["challenge_token"]},
            format="json",
        )
        return login.data["challenge_token"], resp

    def test_exchange_mints_enroll_only_access_without_refresh(self):
        user = _provisioned(mfa_enrollment_required=True)
        _, resp = self._enroll_session(user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "MFA_ENROLL_SESSION")
        self.assertNotIn("refresh", resp.data)

        payload = jwt_provider.handler.decode_token(resp.data["access"], verify=False)
        self.assertTrue(payload["enroll_only"])
        self.assertEqual(payload["user_id"], str(user.pk))

    def test_exchange_is_single_use(self):
        user = _provisioned(mfa_enrollment_required=True)
        token, first = self._enroll_session(user)
        self.assertEqual(first.status_code, 200)
        second = self.client.post(
            reverse("mfa_enroll_exchange"),
            {"challenge_token": token},
            format="json",
        )
        self.assertEqual(second.status_code, 400)
        self.assertEqual(
            second.data["localizable_error"], ERR_400_FIRST_LOGIN_CHALLENGE_INVALID
        )

    def test_exchange_rejects_password_change_challenge(self):
        user = _provisioned(password_change_required=True)
        login = self.client.post(
            reverse("password_login"),
            {"login": user.username, "password": _PW},
            format="json",
        )
        resp = self.client.post(
            reverse("mfa_enroll_exchange"),
            {"challenge_token": login.data["challenge_token"]},
            format="json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_enroll_session_surface_is_cut_down(self):
        user = _provisioned(mfa_enrollment_required=True)
        _, resp = self._enroll_session(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {resp.data['access']}")

        # Denied: everything outside the enrollment surface, structured 403.
        for name, method in (
            ("password_methods", "get"),
            ("sessions", "get"),
            ("passkey_list", "get"),
            ("security_status", "get"),
        ):
            denied = getattr(self.client, method)(reverse(name))
            self.assertEqual(denied.status_code, 403, name)
            self.assertEqual(
                denied.data["localizable_error"], ERR_403_MFA_ENROLLMENT_REQUIRED, name
            )

        # Allowed: TOTP setup within the enroll session.
        setup = self.client.post(reverse("totp_setup"), {}, format="json")
        self.assertEqual(setup.status_code, 200)

        # Allowed: logout.
        out = self.client.post(reverse("logout"), {}, format="json")
        self.assertEqual(out.status_code, 200)

    def test_normal_session_unaffected_by_guard(self):
        user = _make_user()
        access, _ = jwt_provider.create_tokens(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        resp = self.client.get(reverse("password_methods"))
        self.assertEqual(resp.status_code, 200)

    def test_activation_upgrades_to_full_session(self):
        import pyotp

        user = _provisioned(mfa_enrollment_required=True)
        _, resp = self._enroll_session(user)
        access = resp.data["access"]
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")

        setup = self.client.post(reverse("totp_setup"), {}, format="json")
        code = pyotp.TOTP(setup.data["secret"]).now()
        confirm = self.client.post(
            reverse("totp_setup_confirm"), {"code": code}, format="json"
        )
        self.assertEqual(confirm.status_code, 200)
        self.assertTrue(confirm.data["backup_codes"])

        # Full session pair in the SAME response; flag cleared.
        self.assertTrue(confirm.data["tokens"]["access"])
        self.assertTrue(confirm.data["tokens"]["refresh"])
        user.refresh_from_db()
        self.assertFalse(user.mfa_enrollment_required)

        full_payload = jwt_provider.handler.decode_token(
            confirm.data["tokens"]["access"], verify=False
        )
        self.assertNotIn("enroll_only", full_payload)

        # The full token opens the previously-403 surface.
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {confirm.data['tokens']['access']}"
        )
        self.assertEqual(
            self.client.get(reverse("password_methods")).status_code, 200
        )

        # And the activation reached the outbox as user.mfa_enabled.
        payloads = [
            json.loads(row.event_json)["payload"]
            for row in OutboxEvent.objects.filter(topic="user.mfa_enabled")
        ]
        self.assertIn(
            {"user_id": str(user.pk), "factor": "totp"}, payloads
        )

    def test_confirm_without_enroll_session_has_no_tokens(self):
        """A normal session confirming TOTP keeps the old response shape."""
        import pyotp

        user = _make_user()
        access, _ = jwt_provider.create_tokens(user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
        setup = self.client.post(reverse("totp_setup"), {}, format="json")
        code = pyotp.TOTP(setup.data["secret"]).now()
        confirm = self.client.post(
            reverse("totp_setup_confirm"), {"code": code}, format="json"
        )
        self.assertEqual(confirm.status_code, 200)
        self.assertIsNone(confirm.data.get("tokens"))
