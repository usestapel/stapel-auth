"""The single session-issuance gate (org-program §P13) — sessions/guard.py.

The defect this suite pins: ``stapel-auth`` could mark an account
``is_active=False`` and hang first-login policies on it, but only the
password login path ever looked. Everything else — OTP, OAuth, magic link,
QR, passkey, login-grant, SSO, the instant-change paths — minted a full
session without a glance. A deactivated user walked in through OTP (#92);
a forced password change was walked around with a magic link (#90).

The suite is built so that the failure mode *recurs loudly*:

* :class:`CallSiteEnumerationTests` parses the library and asserts every
  ``_issue_session_tokens`` call site declares a ``SessionPath`` label. A new
  issuance path added without one fails here, not in production;
* :class:`DeactivatedUserTableTests` and :class:`FlaggedUserTableTests` walk
  ``SessionPath.ALL`` — the table is the enumeration itself, so a new label
  is automatically under test and a label added without wiring shows up as a
  gap in :meth:`CallSiteEnumerationTests.test_every_label_has_a_call_site`.

The list of paths is *derived*, never maintained by eye — a hand-kept list
is exactly the mechanism by which the SSO path was misfiled as an
"intermediate" and reproduced both holes verbatim.
"""

import ast
import pathlib
import uuid
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APITestCase

from stapel_auth.errors import (
    ERR_401_ACCOUNT_DISABLED,
    ERR_403_MFA_ENROLLMENT_REQUIRED,
    ERR_403_PASSWORD_CHANGE_REQUIRED,
)
from stapel_auth.models import UserSession
from stapel_auth.sessions.guard import (
    SessionIssuanceDenied,
    SessionPath,
    account_disabled_error,
    first_login_error,
    first_login_gate_applies,
    session_precondition_error,
)
from stapel_auth.sessions.views import _issue_session_tokens

User = get_user_model()

_PW = "initial-org-password-1"
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _user(**kw):
    d = dict(
        email=f"gate-{uuid.uuid4().hex[:10]}@example.com",
        username=f"gate_{uuid.uuid4().hex[:10]}",
        password=_PW,
        is_email_verified=True,
        auth_type="email",
    )
    d.update(kw)
    return User.objects.create_user(**d)


# =============================================================================
# The enumeration itself — derived from the source, not maintained by hand
# =============================================================================


def _issuance_call_sites():
    """(file, lineno, declared SessionPath label or None) for every call.

    Walks the library's own source with ``ast``. ``tests/`` and ``build/`` are
    skipped: the former legitimately calls the minter with hand-made
    arguments, the latter is a stale copy of the package.
    """
    found = []
    for path in sorted(_REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(_REPO_ROOT)
        if rel.parts[0] in {"tests", "build", ".venv", "docs"}:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", None)
            if name != "_issue_session_tokens":
                continue
            label = None
            for kw in node.keywords:
                if kw.arg != "path":
                    continue
                val = kw.value
                if (
                    isinstance(val, ast.Attribute)
                    and isinstance(val.value, ast.Name)
                    and val.value.id == "SessionPath"
                ):
                    label = getattr(SessionPath, val.attr, f"<unknown:{val.attr}>")
            found.append((str(rel), node.lineno, label))
    return found


class CallSiteEnumerationTests(TestCase):
    """Structural gate: no issuance path may slip in unlabeled."""

    def test_call_sites_were_found_at_all(self):
        # Guards against the scan silently matching nothing (a green test that
        # proves nothing is worse than a red one).
        self.assertGreaterEqual(len(_issuance_call_sites()), 15)

    def test_every_call_site_declares_a_session_path(self):
        unlabeled = [
            f"{f}:{ln}" for f, ln, label in _issuance_call_sites() if label is None
        ]
        self.assertEqual(
            unlabeled,
            [],
            "every _issue_session_tokens() call must declare path=SessionPath.X "
            "so the gate's scope is explicit and this suite covers it",
        )

    def test_every_call_site_uses_a_known_label(self):
        unknown = [
            f"{f}:{ln} -> {label}"
            for f, ln, label in _issuance_call_sites()
            if label is not None and label not in SessionPath.ALL
        ]
        self.assertEqual(unknown, [])

    def test_every_label_is_actually_wired_somewhere(self):
        """A label with no wiring is a path someone declared and forgot.

        The scan looks for any reference to the label rather than for a
        minter call, so a label used somewhere other than a call site (a
        settings default, a redirect branch) still counts as wired.
        """
        wired = set()
        for path in sorted(_REPO_ROOT.rglob("*.py")):
            rel = path.relative_to(_REPO_ROOT)
            if rel.parts[0] in {"tests", "build", ".venv", "docs"} or rel.name == "guard.py":
                continue
            src = path.read_text()
            for label_attr, label in vars(SessionPath).items():
                if label_attr.isupper() and f"SessionPath.{label_attr}" in src:
                    wired.add(label)
        self.assertEqual(
            SessionPath.ALL - wired,
            set(),
            "declared SessionPath labels that no code path uses",
        )

    def test_sso_is_in_the_enumeration(self):
        """Regression, named explicitly: the design doc classified the SSO
        minter as an *intermediate* path exempt from the gate. It is a final
        minter, and the misfiling reproduced #90 and #92 on SSO word for
        word. Pinned by name so the classification cannot quietly flip back.
        """
        self.assertIn(SessionPath.SSO, SessionPath.ALL)
        wired = {(f, label) for f, _, label in _issuance_call_sites()}
        self.assertIn(("sso_service.py", SessionPath.SSO), wired)


# =============================================================================
# The bypass roster — a different genre: it enumerates CALLERS, not behavior
# =============================================================================

#: Every call to ``create_tokens_for_user`` that does NOT sit inside
#: ``_issue_session_tokens``, with the reason it is allowed to skip the gate.
#: Keyed by ``file::enclosing function``.
#:
#: What each entry must be: a path that resolves an intermediate (mints a
#: session the moment the forcing flag comes off, or mints a deliberately
#: limited one), or a path that runs the precondition predicate itself.
_BYPASS_ALLOWLIST = {
    "sessions/services.py::create_tokens_for_user": (
        "TokenService facade over the primitive — mints no session row and is "
        "not itself an admission path"
    ),
    "sessions/services.py::get_refresh_token_for_user": (
        "TokenService facade over the primitive — same, cookie-shaped return"
    ),
    "password/views.py::change_otp_verify": (
        "re-mint after a mid-flow guest promotion; the caller's own session "
        "was just revoked by the password change"
    ),
    "qr/views.py::confirm": "login_request confirm mints for the already-authenticated scanner",
}


def _direct_mint_callers():
    """``file::function`` for every ``create_tokens_for_user`` call site."""
    callers = []
    for path in sorted(_REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(_REPO_ROOT)
        if rel.parts[0] in {"tests", "build", ".venv", "docs"}:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        # Map each node to its nearest enclosing function.
        enclosing = {}
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(fn):
                    enclosing.setdefault(child, fn.name)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
            if name != "create_tokens_for_user":
                continue
            callers.append(
                (f"{rel}::{enclosing.get(node, '<module>')}", node.lineno)
            )
    return callers


class DirectMintCallerRosterTests(TestCase):
    """Who is allowed to mint a token pair around the gate — enumerated.

    A different genre from the rest of this file: it does not test behavior,
    it enumerates *callers*. ``create_tokens_for_user`` is public and called
    directly from several modules; each such call is a session minted without
    the admission gate. The roster turns "we remember which ones are
    legitimate" into "the build fails when a new one appears".

    **The honest boundary, stated so nobody reads more into it than it does:**
    the allow-list records a *declared intention*, not a verified one. A wrong
    entry passes green. That is exactly how the design document went wrong —
    it classified the SSO minter as an intermediate path and the
    classification was simply false, so SSO reproduced both holes verbatim.
    This test does not protect against a wrong decision. It protects against
    an *unnoticed* one: a new bypass cannot appear without someone writing
    down, here, why it is a bypass.
    """

    def test_scan_finds_the_known_callers(self):
        # A roster test that matches nothing is worse than no roster test.
        # The floor moved 8 -> 4 when the legacy /token/ endpoint and both
        # password-reset verify paths stopped minting around the gate and
        # started calling _issue_session_tokens (audit AUTH-01/AUTH-04).
        # Fewer bypasses is the direction of travel; the floor only exists
        # so a broken scanner cannot pass by finding nothing.
        self.assertGreaterEqual(len(_direct_mint_callers()), 4)

    def test_every_direct_mint_is_inside_the_minter_or_on_the_roster(self):
        unaccounted = sorted(
            f"{key} (line {line})"
            for key, line in _direct_mint_callers()
            if key != "sessions/views.py::_issue_session_tokens"
            and key not in _BYPASS_ALLOWLIST
        )
        self.assertEqual(
            unaccounted,
            [],
            "\n".join(
                [
                    "",
                    "A new caller mints a session pair around the admission gate.",
                    "Every full session must go through "
                    "sessions.views._issue_session_tokens, which enforces "
                    "is_active + the first-login policy (sessions/guard.py).",
                    "",
                    "If this call really does resolve an intermediate — it mints "
                    "right after clearing the forcing flag, or it mints a "
                    "deliberately limited session — add it to "
                    "_BYPASS_ALLOWLIST with the reason. If it does not, route "
                    "it through the minter with a SessionPath label.",
                    "",
                    "Do not add an entry because the test is red. The SSO path "
                    "was 'declared intermediate' for months and was not one.",
                ]
            ),
        )

    def test_allowlist_has_no_stale_entries(self):
        """A bypass that no longer exists must leave the roster, or the roster
        starts describing a codebase that is gone."""
        live = {key for key, _ in _direct_mint_callers()}
        self.assertEqual(
            sorted(set(_BYPASS_ALLOWLIST) - live),
            [],
            "allow-listed bypasses that no longer exist in the source",
        )


# =============================================================================
# Deactivated account: refused on EVERY path, unconditionally, with no oracle
# =============================================================================


class DeactivatedUserTableTests(TestCase):
    """#92 — the table walks every declared issuance path."""

    def test_no_path_issues_a_session_to_a_deactivated_user(self):
        for path in sorted(SessionPath.ALL):
            with self.subTest(path=path):
                user = _user(is_active=False)
                with self.assertRaises(SessionIssuanceDenied) as ctx:
                    _issue_session_tokens(user, None, path=path)
                self.assertEqual(ctx.exception.http_status, 401)
                self.assertEqual(ctx.exception.error_key, ERR_401_ACCOUNT_DISABLED)
                self.assertEqual(
                    UserSession.objects.filter(user=user).count(),
                    0,
                    "a refused issuance must not leave a session row behind",
                )

    def test_undeclared_path_also_refuses(self):
        """Fail-closed: a caller that forgot its label is still gated."""
        user = _user(is_active=False)
        with self.assertRaises(SessionIssuanceDenied):
            _issue_session_tokens(user, None)

    def test_refusal_carries_no_next_step_and_no_account_detail(self):
        user = _user(is_active=False)
        denial = session_precondition_error(user, path=SessionPath.OTP_EMAIL)
        self.assertIsNotNone(denial)
        self.assertIsNone(denial.requires, "a disabled account has no next step")
        self.assertIsNone(denial.challenge_token)
        # No enumeration oracle: nothing in the payload distinguishes this
        # account from any other.
        self.assertEqual(denial.error_params, {})

    def test_is_active_gate_ignores_the_policy_switch(self):
        """The switch scopes the FLAGS only. is_active is not negotiable."""
        user = _user(is_active=False)
        with override_settings(STAPEL_AUTH={"FIRST_LOGIN_GATE_PATHS": []}):
            self.assertIsNotNone(account_disabled_error(user))
            with self.assertRaises(SessionIssuanceDenied):
                _issue_session_tokens(user, None, path=SessionPath.MAGIC_LINK)

    def test_disabled_account_never_receives_a_live_challenge(self):
        """Order matters: refuse before minting anything the account could
        use. A disabled+flagged account must not walk out with a working
        first-login challenge token."""
        user = _user(is_active=False, password_change_required=True)
        denial = session_precondition_error(user, path=SessionPath.MAGIC_LINK)
        self.assertEqual(denial.error_key, ERR_401_ACCOUNT_DISABLED)
        self.assertIsNone(denial.challenge_token)


# =============================================================================
# First-login flags: refused on every path, but always WITH a next step
# =============================================================================


class FlaggedUserTableTests(TestCase):
    """#90 — the wide reading, and the next-step obligation that makes it safe."""

    def test_no_path_issues_a_session_to_a_password_change_flagged_user(self):
        for path in sorted(SessionPath.ALL):
            with self.subTest(path=path):
                user = _user(password_change_required=True)
                with self.assertRaises(SessionIssuanceDenied) as ctx:
                    _issue_session_tokens(user, None, path=path)
                denial = ctx.exception
                self.assertEqual(denial.http_status, 403)
                self.assertEqual(
                    denial.error_key, ERR_403_PASSWORD_CHANGE_REQUIRED
                )
                self.assertEqual(denial.requires, "password_change")
                self.assertTrue(denial.challenge_token)
                self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_no_path_issues_a_session_to_an_mfa_enroll_flagged_user(self):
        for path in sorted(SessionPath.ALL):
            with self.subTest(path=path):
                user = _user(mfa_enrollment_required=True)
                with self.assertRaises(SessionIssuanceDenied) as ctx:
                    _issue_session_tokens(user, None, path=path)
                self.assertEqual(
                    ctx.exception.error_key, ERR_403_MFA_ENROLLMENT_REQUIRED
                )
                self.assertEqual(ctx.exception.requires, "mfa_enroll")
                self.assertTrue(ctx.exception.challenge_token)

    def test_denial_payload_carries_the_next_step(self):
        """The whole reason the wide reading is safe: never a dead 403."""
        user = _user(password_change_required=True)
        denial = first_login_error(user, path=SessionPath.MAGIC_LINK)
        self.assertEqual(
            set(denial.error_params), {"requires", "challenge_token", "expires_in"}
        )
        self.assertEqual(denial.error_params["requires"], "password_change")
        self.assertGreater(denial.error_params["expires_in"], 0)

    def test_challenge_minted_on_any_path_resolves(self):
        """A challenge created by the magic-link path is not second-class:
        the resolver takes nothing but the token."""
        from stapel_auth.password.services import FirstLoginPolicyService

        user = _user(password_change_required=True)
        denial = first_login_error(user, path=SessionPath.MAGIC_LINK)
        resolved = FirstLoginPolicyService.resolve_challenge(
            denial.challenge_token, FirstLoginPolicyService.REQUIRES_PASSWORD_CHANGE
        )
        self.assertEqual(resolved.pk, user.pk)

    def test_mfa_flag_selfheals_for_an_account_with_a_strong_factor(self):
        """Passkey sign-in by a flagged user needs no special case: the
        policy service clears a stale flag on the spot."""
        user = _user(mfa_enrollment_required=True)
        with patch("stapel_core.verification.strong_factors", return_value=["totp"]):
            self.assertIsNone(first_login_error(user, path=SessionPath.PASSKEY_LOGIN))
        user.refresh_from_db()
        self.assertFalse(user.mfa_enrollment_required)


# =============================================================================
# Regression: the ordinary account is untouched
# =============================================================================


class UnflaggedUserRegressionTests(TestCase):
    """Release gate: an active account with no flags logs in as before."""

    def test_every_path_still_issues_a_session(self):
        for path in sorted(SessionPath.ALL):
            with self.subTest(path=path):
                user = _user()
                access, refresh = _issue_session_tokens(user, None, path=path)
                self.assertTrue(access)
                self.assertTrue(refresh)
                self.assertEqual(UserSession.objects.filter(user=user).count(), 1)

    def test_predicate_is_none_for_a_clean_account(self):
        user = _user()
        for path in sorted(SessionPath.ALL):
            self.assertIsNone(session_precondition_error(user, path=path))


# =============================================================================
# The policy switch — both readings are exercised, so a verdict change is a
# config change and not a test rewrite
# =============================================================================


class GateScopeSwitchTests(TestCase):
    """``FIRST_LOGIN_GATE_PATHS`` — which paths the FLAGS block."""

    def test_default_is_the_wide_reading(self):
        from stapel_auth.conf import auth_settings

        self.assertEqual(auth_settings.FIRST_LOGIN_GATE_PATHS, "*")
        for path in sorted(SessionPath.ALL):
            self.assertTrue(first_login_gate_applies(path))

    @override_settings(
        STAPEL_AUTH={"FIRST_LOGIN_GATE_PATHS": ["password", "legacy_token"]}
    )
    def test_narrow_reading_scopes_the_flags_to_the_named_paths(self):
        self.assertTrue(first_login_gate_applies(SessionPath.PASSWORD))
        self.assertTrue(first_login_gate_applies(SessionPath.LEGACY_TOKEN))
        self.assertFalse(first_login_gate_applies(SessionPath.MAGIC_LINK))
        self.assertFalse(first_login_gate_applies(SessionPath.OTP_EMAIL))

    @override_settings(
        STAPEL_AUTH={"FIRST_LOGIN_GATE_PATHS": ["password", "legacy_token"]}
    )
    def test_narrow_reading_lets_a_flagged_user_in_by_otp(self):
        """Documenting exactly what the narrow reading costs: this IS the
        hole #90 was filed for. It is reachable only by explicit config."""
        user = _user(password_change_required=True)
        access, _ = _issue_session_tokens(user, None, path=SessionPath.OTP_EMAIL)
        self.assertTrue(access)

        blocked = _user(password_change_required=True)
        with self.assertRaises(SessionIssuanceDenied):
            _issue_session_tokens(blocked, None, path=SessionPath.PASSWORD)

    @override_settings(STAPEL_AUTH={"FIRST_LOGIN_GATE_PATHS": []})
    def test_flags_can_be_disabled_entirely_but_is_active_survives(self):
        flagged = _user(password_change_required=True)
        self.assertTrue(_issue_session_tokens(flagged, None, path=SessionPath.OTP_EMAIL)[0])

        disabled = _user(is_active=False)
        with self.assertRaises(SessionIssuanceDenied):
            _issue_session_tokens(disabled, None, path=SessionPath.OTP_EMAIL)

    @override_settings(STAPEL_AUTH={"FIRST_LOGIN_GATE_PATHS": []})
    def test_undeclared_path_is_never_exempt(self):
        user = _user(password_change_required=True)
        self.assertTrue(first_login_gate_applies(SessionPath.UNSPECIFIED))
        with self.assertRaises(SessionIssuanceDenied):
            _issue_session_tokens(user, None)


# =============================================================================
# End to end — the shapes a client actually receives
# =============================================================================

_FRONTEND = "https://app.example.com"
_MOCK_OTP = {"USE_MOCK_EMAIL_OTP": True, "MOCK_OTP_CODE": "1234"}


@override_settings(URL_PREFIX="", FRONTEND_URL=_FRONTEND, **_MOCK_OTP)
class OtpPathEndToEndTests(APITestCase):
    """OTP email verify — a JSON path. #90/#92 verbatim."""

    def setUp(self):
        cache.clear()

    def _verify(self, email):
        # The OTP boundary is mocked (as the rest of the suite does); what is
        # under test is what happens AFTER the code checks out.
        with patch(
            "stapel_auth.otp.services.EmailVerificationService.verify_code",
            return_value={"success": True},
        ):
            return self.client.post(
                reverse("email_verify"), {"email": email, "code": "1234"}, format="json"
            )

    def test_deactivated_user_gets_no_session(self):
        user = _user(is_active=False)
        resp = self._verify(user.email)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.data["localizable_error"], ERR_401_ACCOUNT_DISABLED)
        self.assertNotIn("tokens", resp.data)
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_flagged_user_gets_no_session_but_gets_the_next_step(self):
        user = _user(password_change_required=True)
        resp = self._verify(user.email)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(
            resp.data["localizable_error"], ERR_403_PASSWORD_CHANGE_REQUIRED
        )
        self.assertEqual(resp.data["params"]["requires"], "password_change")
        self.assertTrue(resp.data["params"]["challenge_token"])
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_flagged_user_can_finish_the_forced_step_and_get_in(self):
        """The obligation that makes the wide reading humane: a user who
        arrived by OTP is not locked out — the next step works and ends in a
        real session."""
        user = _user(password_change_required=True)
        token = self._verify(user.email).data["params"]["challenge_token"]

        done = self.client.post(
            reverse("password_forced_change"),
            {"challenge_token": token, "new_password": "my-very-own-password-7"},
            format="json",
        )
        self.assertEqual(done.status_code, 200)
        self.assertEqual(done.data["status"], "LOGGED_IN")
        self.assertTrue(done.data["tokens"]["access"])
        user.refresh_from_db()
        self.assertFalse(user.password_change_required)

        # And now the ordinary path works again.
        again = self._verify(user.email)
        self.assertEqual(again.status_code, 200)
        self.assertTrue(again.data["tokens"]["access"])

    def test_clean_user_logs_in_exactly_as_before(self):
        user = _user()
        resp = self._verify(user.email)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data["tokens"]["access"])
        self.assertEqual(UserSession.objects.filter(user=user).count(), 1)


@override_settings(URL_PREFIX="", FRONTEND_URL=_FRONTEND)
class PasswordResetPathEndToEndTests(APITestCase):
    """Password reset — recovery, and therefore an admission (audit AUTH-04).

    Both verify endpoints used to call the low-level mint directly, on the
    theory that a just-completed reset is proof enough. It is not: proving
    control of a mailbox replaces the password, it does not decide whether
    the account may be admitted. A disabled account walked in, a first-login
    obligation was walked around, and the session that came out was
    untracked — not listable, not revocable.

    Email and phone are tested as a pair on purpose: they are copies of one
    another, which is how a fix lands on one and misses the sibling.
    """

    def setUp(self):
        cache.clear()

    def _reset_email(self, user, password="brand-new-password-3"):
        with patch(
            "stapel_auth.otp.services.EmailVerificationService.verify_code",
            return_value={"success": True},
        ):
            return self.client.post(
                reverse("password_reset_email_verify"),
                {"email": user.email, "code": "1234", "new_password": password},
                format="json",
            )

    def _reset_phone(self, user, password="brand-new-password-3"):
        with patch(
            "stapel_auth.otp.services.PhoneVerificationService.verify_code",
            return_value={"success": True},
        ):
            return self.client.post(
                reverse("password_reset_phone_verify"),
                {"phone": user.phone, "code": "1234", "new_password": password},
                format="json",
            )

    def _phone_user(self, **kw):
        # A distinct number per user; the reset lookup keys on it.
        return _user(
            phone=f"+7999{uuid.uuid4().int % 10**7:07d}",
            is_phone_verified=True,
            **kw,
        )

    def test_deactivated_user_gets_no_session_from_an_email_reset(self):
        user = _user(is_active=False)
        resp = self._reset_email(user)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.data["localizable_error"], ERR_401_ACCOUNT_DISABLED)
        self.assertNotIn("tokens", resp.data)
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_deactivated_user_gets_no_session_from_a_phone_reset(self):
        user = self._phone_user(is_active=False)
        resp = self._reset_phone(user)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.data["localizable_error"], ERR_401_ACCOUNT_DISABLED)
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_flagged_user_gets_no_session_but_gets_the_next_step(self):
        user = _user(mfa_enrollment_required=True)
        resp = self._reset_email(user)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(
            resp.data["localizable_error"], ERR_403_MFA_ENROLLMENT_REQUIRED
        )
        self.assertTrue(resp.data["params"]["challenge_token"])
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_the_password_is_still_reset_even_when_admission_is_refused(self):
        """Recovery and admission are separate answers.

        The reset itself succeeded before the gate ran — the user really did
        prove control of the mailbox — so refusing the *session* must not
        silently undo it, or a flagged user is stuck with a password they no
        longer know.
        """
        user = _user(password_change_required=True)
        self._reset_email(user, password="brand-new-password-3")
        user.refresh_from_db()
        self.assertTrue(user.check_password("brand-new-password-3"))

    def test_clean_email_reset_yields_exactly_one_tracked_session(self):
        user = _user()
        resp = self._reset_email(user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "LOGGED_IN")
        self.assertTrue(resp.data["tokens"]["access"])
        self.assertEqual(UserSession.objects.filter(user=user).count(), 1)

    def test_clean_phone_reset_yields_exactly_one_tracked_session(self):
        user = self._phone_user()
        resp = self._reset_phone(user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "LOGGED_IN")
        self.assertEqual(UserSession.objects.filter(user=user).count(), 1)

    def test_the_reset_kills_the_sessions_that_existed_before_it(self):
        """The point of recovery: the attacker's session does not survive it.

        The one session left standing is the one the reset just issued.
        """
        user = _user()
        _issue_session_tokens(user, None, path=SessionPath.PASSWORD)
        _issue_session_tokens(user, None, path=SessionPath.OTP_EMAIL)
        self.assertEqual(
            UserSession.objects.filter(user=user, is_revoked=False).count(), 2
        )

        self.assertEqual(self._reset_email(user).status_code, 200)
        self.assertEqual(
            UserSession.objects.filter(user=user, is_revoked=False).count(), 1
        )

    def test_the_reset_is_audited_as_a_login(self):
        """A recovery that admits somebody must leave the same evidence any
        other admission leaves — the direct mint left none."""
        from stapel_auth.models import AuthAuditLog

        user = _user()
        self.assertEqual(self._reset_email(user).status_code, 200)
        self.assertTrue(
            AuthAuditLog.objects.filter(user=user, event_type="login_success").exists()
        )


@override_settings(URL_PREFIX="", FRONTEND_URL=_FRONTEND)
class MagicLinkPathEndToEndTests(APITestCase):
    """Magic link — a browser REDIRECT path: never a raw JSON dead end."""

    def setUp(self):
        cache.clear()

    def _verify(self, user, redirect_url="/dash"):
        from stapel_auth.magic_link.services import MagicLinkService

        token = MagicLinkService.create(user, redirect_url=redirect_url)
        return self.client.get(reverse("magic_verify"), {"token": token})

    def test_flagged_user_is_redirected_to_the_challenge_not_to_json(self):
        user = _user(password_change_required=True)
        resp = self._verify(user)
        self.assertEqual(resp.status_code, 302)
        loc = resp["Location"]
        self.assertTrue(loc.startswith(f"{_FRONTEND}/login?"), loc)
        self.assertIn("first_login=password_change", loc)
        self.assertIn("challenge_token=", loc)
        self.assertIn("next=%2Fdash", loc)
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_flagged_user_can_finish_the_step_from_the_magic_link(self):
        """The lock-out scenario the wide reading has to survive: the user
        clicked a link in an email and has no idea what their org-set
        password is. ``/password/forced-change/`` never asks for it."""
        from urllib.parse import parse_qs, urlparse

        user = _user(password_change_required=True)
        loc = self._verify(user)["Location"]
        token = parse_qs(urlparse(loc).query)["challenge_token"][0]

        done = self.client.post(
            reverse("password_forced_change"),
            {"challenge_token": token, "new_password": "my-very-own-password-7"},
            format="json",
        )
        self.assertEqual(done.status_code, 200)
        self.assertEqual(done.data["status"], "LOGGED_IN")

    def test_clean_user_still_lands_on_the_redirect_target(self):
        user = _user()
        resp = self._verify(user)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], "/dash")
        self.assertEqual(UserSession.objects.filter(user=user).count(), 1)


@override_settings(URL_PREFIX="", FRONTEND_URL=_FRONTEND)
class OAuthPathEndToEndTests(APITestCase):
    """OAuth access-token login — a JSON path."""

    def setUp(self):
        cache.clear()

    def _login(self, email):
        from stapel_auth.oauth_providers import OAuthUserData

        with patch(
            "stapel_auth.oauth.services.OAuthService.get_user_data",
            return_value=OAuthUserData(
                id=f"gh-{uuid.uuid4().hex[:8]}",
                email=email,
                username="OAuth User",
                avatar="",
                email_verified=True,
            ),
        ):
            return self.client.post(
                reverse("oauth_login"),
                {"provider": "google", "access_token": "fake"},
                format="json",
            )

    def test_deactivated_user_gets_no_session(self):
        user = _user(is_active=False)
        resp = self._login(user.email)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.data["localizable_error"], ERR_401_ACCOUNT_DISABLED)
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_flagged_user_gets_the_next_step(self):
        user = _user(mfa_enrollment_required=True)
        resp = self._login(user.email)
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(
            resp.data["localizable_error"], ERR_403_MFA_ENROLLMENT_REQUIRED
        )
        self.assertTrue(resp.data["params"]["challenge_token"])

    def test_clean_user_logs_in(self):
        user = _user()
        resp = self._login(user.email)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data["tokens"]["access"])


@override_settings(URL_PREFIX="", FRONTEND_URL=_FRONTEND, STAPEL_AUTH={"AUTH_LOGIN_GRANT": True})
class LoginGrantPathEndToEndTests(APITestCase):
    def setUp(self):
        cache.clear()

    def _exchange(self, user):
        from stapel_auth.login_grant.services import LoginGrantService

        token = LoginGrantService.issue(email=user.email)
        return self.client.post(
            reverse("grant_exchange"), {"grant_token": token}, format="json"
        )

    def test_flagged_user_gets_the_next_step(self):
        user = _user(password_change_required=True)
        resp = self._exchange(user)
        self.assertEqual(resp.status_code, 403)
        self.assertTrue(resp.data["params"]["challenge_token"])
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_clean_user_logs_in(self):
        user = _user()
        resp = self._exchange(user)
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data["tokens"]["access"])


@override_settings(FRONTEND_URL=_FRONTEND, BACKEND_URL=_FRONTEND)
class SsoPathEndToEndTests(TestCase):
    """SSO ACS — the path the design doc misfiled as intermediate.

    Also covers the second hole in the same method: ``_resolve_sso_user``'s
    ``get_or_create`` hands back an EXISTING deactivated user unchanged
    (``defaults={'is_active': True}`` only fires on create), so the ACS used
    to hand a live session to a deactivated account.
    """

    def setUp(self):
        cache.clear()
        from stapel_auth.models import Organization

        self.org = Organization.objects.create(
            name="Acme Corp", slug=f"acme{uuid.uuid4().hex[:6]}", domain="acmecorp.com"
        )
        self.request = RequestFactory().post("/auth/api/v1/sso/acme/saml/acs/")

    def _issue(self, user):
        from stapel_auth.sessions.services import LoginNotificationService
        from stapel_auth.sso_service import SSOUserService

        with patch.object(LoginNotificationService, "check_and_notify"):
            return SSOUserService.issue_session_and_redirect(
                user, self.org, self.request
            )

    def test_deactivated_user_gets_no_session(self):
        user = _user(is_active=False)
        resp = self._issue(user)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], f"{_FRONTEND}/login?error=account_disabled")
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)
        self.assertFalse(any(resp.cookies))

    def test_flagged_user_is_redirected_to_the_challenge(self):
        user = _user(password_change_required=True)
        resp = self._issue(user)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("first_login=password_change", resp["Location"])
        self.assertIn("challenge_token=", resp["Location"])
        self.assertEqual(UserSession.objects.filter(user=user).count(), 0)

    def test_clean_user_gets_exactly_one_session_and_the_sso_audit_verb(self):
        """Regression on the collapse of the duplicated minter body: still
        one session row (the old UNIQUE(jti) crash), still ``sso_login``."""
        from stapel_auth.models import AuthAuditLog

        user = _user()
        resp = self._issue(user)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp["Location"], f"{_FRONTEND}/")
        self.assertTrue(any(resp.cookies))
        self.assertEqual(UserSession.objects.filter(user=user).count(), 1)
        self.assertTrue(
            AuthAuditLog.objects.filter(user=user, event_type="sso_login").exists()
        )


@override_settings(URL_PREFIX="", STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True})
class PasswordPathUnchangedTests(APITestCase):
    """The dedup must not move the password path. Same shapes as before."""

    def setUp(self):
        cache.clear()

    def _login(self, user):
        return self.client.post(
            reverse("password_login"),
            {"login": user.username, "password": _PW},
            format="json",
        )

    def test_disabled_account_still_401_with_no_challenge(self):
        user = _user(is_active=False)
        resp = self._login(user)
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(resp.data["localizable_error"], ERR_401_ACCOUNT_DISABLED)
        self.assertEqual(resp.data["params"], {})

    def test_flagged_account_still_gets_the_interactive_200_challenge(self):
        user = _user(password_change_required=True)
        resp = self._login(user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "FIRST_LOGIN_REQUIRED")
        self.assertEqual(resp.data["requires"], "password_change")
        self.assertTrue(resp.data["challenge_token"])

    def test_clean_account_logs_in(self):
        user = _user()
        resp = self._login(user)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data["status"], "LOGGED_IN")
