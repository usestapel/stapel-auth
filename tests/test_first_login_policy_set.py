"""First-login policies are a SET of independent demands, not a choice (#90).

The defect. ``auth.provision_user`` took one ``first_login_policy`` string
and spelled the account creation

    password_change_required=(policy == "password_change"),
    mfa_enrollment_required=(policy == "mfa_enroll"),

so asking for either demand actively **cleared** the other. An org could
not require both a password rotation and a second factor before a
provisioned account is let in — not because the machinery was missing, but
because of that one payload field. The user row has carried two independent
booleans since Wave 0; ``FirstLoginPolicyService.required_intermediate``
has always resolved them in order (password change first, then MFA
enrolment); ``POST /password/forced-change/`` has always chained into the
mfa_enrol intermediate when both were up. Everything downstream was ready.
The checkboxes in the invite modal were inert because of the API in front
of it.

Why this is no longer decorative. 0.15.0 put ``first_login_error`` inside
``_issue_session_tokens``, the single minter every full-session path funnels
through (``sessions/guard.py``), with ``FIRST_LOGIN_GATE_PATHS`` defaulting
to ``'*'``. Before that, a flag was enforced on the password path and walked
around by OTP or a magic link. A policy raised here now blocks admission on
all of them, so "both flags up" is a real precondition rather than two
booleans in a table.

Two surfaces are pinned here:

* :class:`ProvisionUserPolicySetTests` — the provisioning payload takes a
  set, honours every member of it, and still understands the deprecated
  singular key so a consumer pinned to stapel-workspaces < 0.13 keeps
  working.
* :class:`ApplyFirstLoginPoliciesTests` — the new
  ``auth.apply_first_login_policies`` Function, which raises policies on an
  account that already exists (the invite-acceptance seam). Additive by
  contract: the flags are per-account while the callers are per-org, so
  subtraction would let one tenant lower another tenant's bar.
"""
import json
import uuid
from pathlib import Path

from django.contrib.auth import get_user_model
from django.test import TestCase

from stapel_core.comm import call
from stapel_core.django.api.errors import ERR_400_BAD_REQUEST, ERR_404_NOT_FOUND

from stapel_auth.password.services import FirstLoginPolicyService

User = get_user_model()

BOTH = ["password_change", "mfa_enroll"]


def _slug() -> str:
    return f"org{uuid.uuid4().hex[:8]}"


def _provision(**overrides):
    payload = {"username": f"{_slug()}/alice"}
    payload.update(overrides)
    if "first_login_policies" not in payload and "first_login_policy" not in payload:
        payload["first_login_policies"] = []
    return call("auth.provision_user", payload)


class ProvisionUserPolicySetTests(TestCase):
    def test_both_policies_at_once(self):
        """The whole bug in one assertion.

        Under the old payload this was unrepresentable: whichever string
        you sent set one flag and cleared the other.
        """
        result = _provision(first_login_policies=BOTH)
        self.assertNotIn("error", result)
        user = User.objects.get(pk=result["user_id"])
        self.assertTrue(user.password_change_required)
        self.assertTrue(user.mfa_enrollment_required)

    def test_both_policies_are_resolved_in_order_not_collapsed(self):
        """Two demands, resolved one after the other — not one demand.

        ``required_intermediate`` answers ``password_change`` first; the
        account still owes the MFA enrolment after that, which is what
        makes the pair meaningful rather than decorative.
        """
        result = _provision(first_login_policies=BOTH)
        user = User.objects.get(pk=result["user_id"])
        self.assertEqual(
            FirstLoginPolicyService.required_intermediate(user), "password_change"
        )
        user.password_change_required = False
        user.save(update_fields=["password_change_required"])
        self.assertEqual(
            FirstLoginPolicyService.required_intermediate(user), "mfa_enroll"
        )

    def test_single_policy_does_not_clear_the_other(self):
        result = _provision(first_login_policies=["mfa_enroll"])
        user = User.objects.get(pk=result["user_id"])
        self.assertFalse(user.password_change_required)
        self.assertTrue(user.mfa_enrollment_required)

    def test_empty_set_means_no_first_login_step(self):
        """A deliberate "none" — an org may want neither demand."""
        result = _provision(first_login_policies=[])
        user = User.objects.get(pk=result["user_id"])
        self.assertFalse(user.password_change_required)
        self.assertFalse(user.mfa_enrollment_required)
        self.assertIsNone(FirstLoginPolicyService.required_intermediate(user))

    def test_deprecated_singular_key_still_understood(self):
        """A consumer pinned to stapel-workspaces < 0.13 keeps working."""
        result = _provision(first_login_policy="password_change")
        self.assertNotIn("error", result)
        user = User.objects.get(pk=result["user_id"])
        self.assertTrue(user.password_change_required)
        self.assertFalse(user.mfa_enrollment_required)

    def test_plural_key_wins_over_the_deprecated_one(self):
        result = _provision(
            first_login_policies=["mfa_enroll"],
            first_login_policy="password_change",
        )
        user = User.objects.get(pk=result["user_id"])
        self.assertFalse(user.password_change_required)
        self.assertTrue(user.mfa_enrollment_required)

    def test_neither_key_is_a_structured_failure_not_an_empty_set(self):
        """Omission by typo must not quietly provision an unguarded account.

        "No first-login step" is a decision, and a caller makes it by
        sending ``[]``. A missing key is a mistake and says so.
        """
        result = call("auth.provision_user", {"username": f"{_slug()}/bob"})
        self.assertEqual(result, {"error": ERR_400_BAD_REQUEST})
        self.assertFalse(User.objects.filter(username__endswith="/bob").exists())

    def test_unknown_policy_is_a_structured_failure(self):
        result = _provision(first_login_policies=["password_change", "sudo"])
        self.assertEqual(result, {"error": ERR_400_BAD_REQUEST})

    def test_a_bare_string_is_not_a_policy_set(self):
        """``"password_change"`` iterates into characters; refuse it."""
        result = _provision(first_login_policies="password_change")
        self.assertEqual(result, {"error": ERR_400_BAD_REQUEST})

    def test_policy_failure_creates_no_account(self):
        username = f"{_slug()}/carol"
        _provision(username=username, first_login_policies=["nope"])
        self.assertFalse(User.objects.filter(username=username).exists())


class ApplyFirstLoginPoliciesTests(TestCase):
    """``auth.apply_first_login_policies`` — the invite-acceptance seam."""

    def _user(self, **kwargs):
        return User.objects.create_user(
            username=f"u-{uuid.uuid4().hex[:8]}",
            email=f"{uuid.uuid4().hex[:8]}@example.com",
            password="correct-horse-battery-staple-9",
            **kwargs,
        )

    def _apply(self, user, policies):
        return call(
            "auth.apply_first_login_policies",
            {"user_id": str(user.pk), "policies": policies},
        )

    def test_raises_both_policies(self):
        user = self._user()
        self.assertEqual(self._apply(user, BOTH), {"applied": BOTH})
        user.refresh_from_db()
        self.assertTrue(user.password_change_required)
        self.assertTrue(user.mfa_enrollment_required)

    def test_is_additive_never_subtractive(self):
        """One org's demand must not lower another org's.

        The flags live on the ACCOUNT; the callers are per-ORG. A
        subtractive contract would let the second workspace a user joins
        quietly clear the precondition the first one set.
        """
        user = self._user(password_change_required=True)
        self.assertEqual(self._apply(user, ["mfa_enroll"]), {"applied": ["mfa_enroll"]})
        user.refresh_from_db()
        self.assertTrue(user.password_change_required)
        self.assertTrue(user.mfa_enrollment_required)

    def test_empty_policy_set_changes_nothing(self):
        user = self._user(password_change_required=True)
        self.assertEqual(self._apply(user, []), {"applied": []})
        user.refresh_from_db()
        self.assertTrue(user.password_change_required)

    def test_already_outstanding_policy_is_not_reported_as_applied(self):
        user = self._user(mfa_enrollment_required=True)
        self.assertEqual(self._apply(user, ["mfa_enroll"]), {"applied": []})

    def test_mfa_enroll_is_skipped_for_an_account_that_already_has_a_factor(self):
        """A demand with nothing left to do is not a demand.

        Raising it would bounce a user who already carries a strong factor
        into an enrolment screen they have no enrolment to make. (The login
        path self-heals this too, but not raising it is cheaper and does
        not need a login to happen first.)
        """
        user = self._user(phone="+79991230001", is_phone_verified=True)
        self.assertEqual(self._apply(user, BOTH), {"applied": ["password_change"]})
        user.refresh_from_db()
        self.assertFalse(user.mfa_enrollment_required)

    def test_unknown_user_is_a_structured_failure_not_a_silent_noop(self):
        """This Function makes a change; it must say whether it happened.

        Deliberately NOT the "absence means defaults" contract of
        ``auth.verification.policy`` / ``auth.mfa_status`` — those answer
        questions, and an unknown user there legitimately means "no
        preferences". Here a caller that already resolved the account and
        gets a cheerful no-op would believe a security precondition landed
        when it did not.
        """
        result = call(
            "auth.apply_first_login_policies",
            {"user_id": str(uuid.uuid4()), "policies": ["mfa_enroll"]},
        )
        self.assertEqual(result, {"error": ERR_404_NOT_FOUND})

    def test_malformed_user_id_is_a_structured_failure(self):
        result = call(
            "auth.apply_first_login_policies",
            {"user_id": "not-a-uuid", "policies": ["mfa_enroll"]},
        )
        self.assertEqual(result, {"error": ERR_404_NOT_FOUND})

    def test_unknown_policy_is_a_structured_failure(self):
        user = self._user()
        self.assertEqual(self._apply(user, ["sudo"]), {"error": ERR_400_BAD_REQUEST})
        user.refresh_from_db()
        self.assertFalse(user.password_change_required)
        self.assertFalse(user.mfa_enrollment_required)


class PolicyCanonTests(TestCase):
    """The policy vocabulary and the flag mapping have one home."""

    def test_normalize_is_order_stable_and_deduplicated(self):
        normalize = FirstLoginPolicyService.normalize_policies
        self.assertEqual(normalize(["mfa_enroll", "password_change"]), BOTH)
        self.assertEqual(normalize({"password_change", "mfa_enroll"}), BOTH)
        self.assertEqual(normalize(["mfa_enroll", "mfa_enroll"]), ["mfa_enroll"])

    def test_normalize_rejects_the_shapes_a_caller_gets_wrong(self):
        normalize = FirstLoginPolicyService.normalize_policies
        for bad in ("password_change", None, 7, ["password_change", "sudo"], [""]):
            self.assertIsNone(normalize(bad), bad)

    def test_flag_kwargs_names_every_flag_not_only_the_raised_ones(self):
        """A create call listing only the True ones inherits model defaults
        for the rest — which is exactly how "set one, clear the other"
        survives a refactor unnoticed."""
        self.assertEqual(
            FirstLoginPolicyService.flag_kwargs(["mfa_enroll"]),
            {"password_change_required": False, "mfa_enrollment_required": True},
        )
        self.assertEqual(
            set(FirstLoginPolicyService.flag_kwargs([])),
            set(FirstLoginPolicyService.POLICY_FLAGS.values()),
        )

    def test_policies_and_flags_cover_each_other(self):
        self.assertEqual(
            set(FirstLoginPolicyService.POLICIES),
            set(FirstLoginPolicyService.POLICY_FLAGS),
        )


class CommittedSchemaSyncTests(TestCase):
    """The committed schema files are the cross-service contract."""

    def _committed(self, name):
        import stapel_auth

        path = Path(stapel_auth.__file__).parent / "schemas" / "functions" / name
        return json.loads(path.read_text())

    def test_apply_first_login_policies_schema_file(self):
        from stapel_auth.functions import APPLY_FIRST_LOGIN_POLICIES_SCHEMA

        committed = self._committed("auth.apply_first_login_policies.json")
        for key in ("type", "properties", "required", "additionalProperties"):
            self.assertEqual(
                committed[key], APPLY_FIRST_LOGIN_POLICIES_SCHEMA[key], key
            )

    def test_provision_user_no_longer_requires_a_single_policy(self):
        committed = self._committed("auth.provision_user.json")
        self.assertEqual(committed["required"], ["username"])
        self.assertIn("first_login_policies", committed["properties"])
