"""``auth.admin_reset_password`` — the credential half of #110.

An organization administrator must be able to reset a member's password.
The temptation is to let the calling service do it: resolve the user, call
``set_password``, save. That version is wrong in four separate ways, and
each of them is a test below.

* **The old sessions survive.** A reset that leaves live sessions standing
  does not recover an account — whoever is already inside stays inside. The
  reset revokes them and blacklists the JTIs.
* **The new password is permanent.** Somebody other than the account owner
  now knows it. It has to stop working at its first use, which is exactly
  what the first-login machinery is for (#90): the reset raises
  ``password_change`` by default, and the 0.15.0 session guard makes that
  demand hold on all 19 issuance paths rather than only the password form.
* **Nobody knows who did it.** "Who reset this password" must be answerable
  from auth's own journal, not only from the calling service's events, so
  the actor lands on an ``AuthAuditLog`` row.
* **A superuser can be reset by an org admin.** Org administrator is a role
  inside one workspace; staff is a role over the whole deployment. The
  first must never be a route to the second, and that boundary is auth's
  to hold — the caller does not know who is staff.
"""
import json
import uuid
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from stapel_core.comm import call
from stapel_core.django.api.errors import ERR_400_BAD_REQUEST, ERR_404_NOT_FOUND

from stapel_auth.errors import ERR_403_PRIVILEGED_ACCOUNT
from stapel_auth.models import AuthAuditLog, AuthEventType, UserSession

User = get_user_model()

OLD_PW = "correct-horse-battery-staple-9"


def _user(**kwargs):
    return User.objects.create_user(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        password=OLD_PW,
        **kwargs,
    )


def _session(user, jti=None):
    return UserSession.objects.create(
        user=user,
        jti=jti or uuid.uuid4().hex,
        access_jti=uuid.uuid4().hex,
        expires_at=timezone.now() + timezone.timedelta(days=1),
    )


def _reset(user, **overrides):
    payload = {"user_id": str(user.pk)}
    payload.update(overrides)
    return call("auth.admin_reset_password", payload)


class AdminResetPasswordTests(TestCase):
    def test_generated_password_replaces_the_old_one_and_is_returned_once(self):
        user = _user()
        result = _reset(user)
        self.assertNotIn("error", result)
        generated = result["generated_password"]
        self.assertGreaterEqual(len(generated), 16)  # ~128 bits urlsafe

        user.refresh_from_db()
        self.assertTrue(user.check_password(generated))
        self.assertFalse(user.check_password(OLD_PW))

    def test_admin_chosen_password_is_not_echoed_back(self):
        """The caller already has it; returning it would only add a copy."""
        user = _user()
        result = _reset(user, password="another-correct-horse-42")
        self.assertNotIn("generated_password", result)
        user.refresh_from_db()
        self.assertTrue(user.check_password("another-correct-horse-42"))

    def test_weak_admin_chosen_password_is_refused(self):
        """The deployment's own password canon, not a second opinion here."""
        from django.test import override_settings

        user = _user()
        with override_settings(
            AUTH_PASSWORD_VALIDATORS=[
                {
                    "NAME": "django.contrib.auth.password_validation."
                    "MinimumLengthValidator"
                }
            ]
        ):
            result = _reset(user, password="short")
        self.assertEqual(result, {"error": ERR_400_BAD_REQUEST})
        user.refresh_from_db()
        self.assertTrue(user.check_password(OLD_PW), "the old password must stand")


class SessionsDieWithTheOldPasswordTests(TestCase):
    """A reset that leaves live sessions standing does not recover anything."""

    def test_every_session_is_revoked(self):
        user = _user()
        _session(user)
        _session(user)
        result = _reset(user)
        self.assertEqual(result["sessions_revoked"], 2)
        self.assertEqual(
            UserSession.objects.filter(user=user, is_revoked=False).count(), 0
        )

    def test_another_users_sessions_are_untouched(self):
        user, bystander = _user(), _user()
        _session(user)
        keep = _session(bystander)
        _reset(user)
        keep.refresh_from_db()
        self.assertFalse(keep.is_revoked)

    def test_count_is_reported_for_an_account_with_no_sessions(self):
        self.assertEqual(_reset(_user())["sessions_revoked"], 0)


class ResetPasswordIsTemporaryTests(TestCase):
    """Somebody other than the owner knows this password now."""

    def test_password_change_is_demanded_by_default(self):
        user = _user()
        result = _reset(user)
        self.assertEqual(result["first_login_policies_applied"], ["password_change"])
        user.refresh_from_db()
        self.assertTrue(user.password_change_required)

    def test_an_org_may_demand_mfa_enrolment_as_well(self):
        """Independent since #90 — the two compose."""
        user = _user()
        result = _reset(user, first_login_policies=["password_change", "mfa_enroll"])
        self.assertEqual(
            result["first_login_policies_applied"], ["password_change", "mfa_enroll"]
        )
        user.refresh_from_db()
        self.assertTrue(user.password_change_required)
        self.assertTrue(user.mfa_enrollment_required)

    def test_suppressing_the_demand_is_possible_and_explicit(self):
        user = _user()
        result = _reset(user, first_login_policies=[])
        self.assertEqual(result["first_login_policies_applied"], [])
        user.refresh_from_db()
        self.assertFalse(user.password_change_required)

    def test_malformed_policy_set_refuses_the_whole_reset(self):
        user = _user()
        self.assertEqual(
            _reset(user, first_login_policies=["sudo"]), {"error": ERR_400_BAD_REQUEST}
        )
        user.refresh_from_db()
        self.assertTrue(user.check_password(OLD_PW))


class AuditTrailTests(TestCase):
    """Answerable from auth's own journal, not only the caller's events."""

    def test_the_actor_is_on_the_audit_row(self):
        user, admin = _user(), _user()
        _reset(user, actor_id=str(admin.pk), reason="ticket SUP-42")
        row = AuthAuditLog.objects.filter(
            user=user, event_type=AuthEventType.PASSWORD_RESET
        ).latest("created_at")
        self.assertEqual(row.metadata["actor_id"], str(admin.pk))
        self.assertEqual(row.metadata["via"], "admin_reset")
        self.assertEqual(row.metadata["reason"], "ticket SUP-42")

    def test_the_audit_row_carries_no_credential_material(self):
        user = _user()
        result = _reset(user)
        row = AuthAuditLog.objects.filter(
            user=user, event_type=AuthEventType.PASSWORD_RESET
        ).latest("created_at")
        self.assertNotIn(result["generated_password"], json.dumps(row.metadata))

    def test_an_admin_reset_is_distinguishable_from_a_self_service_one(self):
        """``via`` exists so a security review can tell them apart.

        A user completing the OTP reset flow and an administrator resetting
        somebody else's password are the same event type on the same model;
        without the discriminator the journal cannot answer "which of these
        were done TO someone".
        """
        user = _user()
        _reset(user)
        row = AuthAuditLog.objects.filter(user=user).latest("created_at")
        self.assertEqual(row.metadata["via"], "admin_reset")


class PrivilegedAccountsAreOutOfReachTests(TestCase):
    """Org administrator is a role inside one workspace. Staff is not.

    The boundary is auth's to hold: the calling service knows who
    administers a workspace, and nothing about who administers the
    deployment.
    """

    def test_staff_account_is_refused(self):
        user = _user(is_staff=True)
        self.assertEqual(_reset(user), {"error": ERR_403_PRIVILEGED_ACCOUNT})
        user.refresh_from_db()
        self.assertTrue(user.check_password(OLD_PW))

    def test_superuser_account_is_refused(self):
        user = _user(is_superuser=True)
        self.assertEqual(_reset(user), {"error": ERR_403_PRIVILEGED_ACCOUNT})
        user.refresh_from_db()
        self.assertTrue(user.check_password(OLD_PW))

    def test_a_refused_privileged_reset_touches_nothing(self):
        user = _user(is_staff=True)
        session = _session(user)
        _reset(user)
        session.refresh_from_db()
        self.assertFalse(session.is_revoked)
        user.refresh_from_db()
        self.assertFalse(user.password_change_required)
        self.assertFalse(
            AuthAuditLog.objects.filter(
                user=user, event_type=AuthEventType.PASSWORD_RESET
            ).exists()
        )


class UnknownTargetTests(TestCase):
    def test_unknown_user_is_a_structured_failure(self):
        result = call(
            "auth.admin_reset_password", {"user_id": str(uuid.uuid4())}
        )
        self.assertEqual(result, {"error": ERR_404_NOT_FOUND})

    def test_malformed_user_id_is_the_same_structured_failure(self):
        """Same answer for "not a uuid" and "no such uuid".

        The caller builds its own anti-oracle on top; this seam must not
        hand it two different shapes to leak with.
        """
        result = call("auth.admin_reset_password", {"user_id": "not-a-uuid"})
        self.assertEqual(result, {"error": ERR_404_NOT_FOUND})


class CommittedSchemaSyncTests(TestCase):
    def test_admin_reset_password_schema_file(self):
        import stapel_auth
        from stapel_auth.functions import ADMIN_RESET_PASSWORD_SCHEMA

        path = (
            Path(stapel_auth.__file__).parent
            / "schemas"
            / "functions"
            / "auth.admin_reset_password.json"
        )
        committed = json.loads(path.read_text())
        for key in ("type", "properties", "required", "additionalProperties"):
            self.assertEqual(committed[key], ADMIN_RESET_PASSWORD_SCHEMA[key], key)
