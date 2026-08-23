"""``User.last_login`` — the column every login flow in this module ignored.

The defect, in one sentence: Django stamps ``last_login`` from
``update_last_login``, a receiver of the ``user_logged_in`` signal that only
``django.contrib.auth.login`` sends, and **not one** flow here uses session
login — every one of them mints a JWT. So the column stayed NULL for accounts
that had been logging in for months, and hosts that read it were told those
accounts had never signed in. Found in production: a billing page filtering
``last_login IS NOT NULL`` returned nobody, while this module's own
``auth_audit_log`` listed the very logins it was missing.

Three claims are pinned here, and they are the three halves of the fix:

* **every** token-issuing authentication stamps — not a list of flows someone
  remembered, but the choke point walked by ``SessionPath.ALL`` plus an AST
  gate over the minters that legitimately bypass it, so a login path added
  tomorrow is covered without anyone editing this file;
* **refresh does not** — presenting a live refresh token proves a session is
  still alive, not that anybody authenticated. Stamping there would make
  ``last_login`` mean "last request by a logged-in browser", which is a
  different (and much less useful) column;
* **the backfill fills only NULLs**, from successful-login audit rows, and
  leaves accounts with no such row alone.
"""

import ast
import datetime
import pathlib
import uuid
from importlib import import_module
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from stapel_auth.models import AuthAuditLog
from stapel_auth.sessions.guard import SessionPath
from stapel_auth.sessions.services import stamp_last_login
from stapel_auth.sessions.views import _issue_session_tokens

User = get_user_model()

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PW = "stamp-pass-123"


def _user(**kw):
    d = dict(
        email=f"stamp-{uuid.uuid4().hex[:10]}@example.com",
        username=f"stamp_{uuid.uuid4().hex[:10]}",
        password=_PW,
        is_email_verified=True,
        auth_type="email",
    )
    d.update(kw)
    return User.objects.create_user(**d)


def _bearer_client_for(user) -> APIClient:
    from stapel_core.django.jwt.provider import jwt_provider

    access, _ = jwt_provider.create_tokens(user)
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {access}")
    return client


# =============================================================================
# The helper itself
# =============================================================================


class StampHelperTests(TestCase):
    def test_stamps_and_persists(self):
        user = _user()
        self.assertIsNone(user.last_login)
        before = timezone.now()
        self.assertTrue(stamp_last_login(user))
        user.refresh_from_db()
        self.assertIsNotNone(user.last_login)
        self.assertGreaterEqual(user.last_login, before)

    def test_writes_only_the_one_column(self):
        """``update_fields=["last_login"]`` is not cosmetic: it is what lets
        the projection observer skip its pre-save SELECT on the hottest write
        in the module (user_projection.PROJECTED_FIELDS)."""
        user = _user()
        with patch.object(User, "save", autospec=True) as save:
            stamp_last_login(user)
        save.assert_called_once()
        self.assertEqual(save.call_args.kwargs["update_fields"], ["last_login"])

    def test_unsaved_user_is_skipped_not_crashed(self):
        """The pk is a UUID with a default, so an unsaved instance already
        has one — ``pk is not None`` is not the same question as "is this row
        in the database", and an update_fields save against it updates
        nothing while looking like it worked."""
        unsaved = User(username="never-saved")
        self.assertIsNotNone(unsaved.pk)
        self.assertFalse(stamp_last_login(unsaved))
        self.assertFalse(User.objects.filter(pk=unsaved.pk).exists())

    def test_none_is_skipped(self):
        self.assertFalse(stamp_last_login(None))

    def test_a_failing_write_cannot_fail_the_login(self):
        """A bookkeeping column must never be able to refuse a session."""
        user = _user()
        with patch.object(User, "save", side_effect=RuntimeError("db is on fire")):
            self.assertFalse(stamp_last_login(user))


# =============================================================================
# Every issuance path — the table is SessionPath.ALL, not a hand-kept list
# =============================================================================


class ChokePointStampTests(TestCase):
    """Walks the same enumeration the session gate walks (see
    ``test_session_issuance_gate.py``). A new login flow declares a
    ``SessionPath`` label to get through the gate at all, which puts it in
    this table automatically — the stamp cannot be forgotten by a flow that
    did not exist when this file was written."""

    def test_every_path_stamps_last_login(self):
        for path in sorted(SessionPath.ALL):
            with self.subTest(path=path):
                user = _user()
                self.assertIsNone(user.last_login)
                _issue_session_tokens(user, None, path=path)
                user.refresh_from_db()
                self.assertIsNotNone(
                    user.last_login, f"{path} issued a session without stamping"
                )

    def test_a_refused_issuance_does_not_stamp(self):
        """A denial is not a login. A deactivated account must not come out
        of a refused attempt looking like it signed in."""
        from stapel_auth.sessions.guard import SessionIssuanceDenied

        user = _user(is_active=False)
        with self.assertRaises(SessionIssuanceDenied):
            _issue_session_tokens(user, None, path=SessionPath.PASSWORD)
        user.refresh_from_db()
        self.assertIsNone(user.last_login)


# =============================================================================
# Real flows over HTTP — the wiring, not just the primitive
# =============================================================================


@override_settings(STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True})
class LoginFlowStampTests(APITestCase):
    def setUp(self):
        self.client = APIClient()

    def test_password_login_stamps(self):
        user = _user(username="pw_stamper", password=_PW)
        resp = self.client.post(
            reverse("password_login"), {"login": "pw_stamper", "password": _PW}, format="json"
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertIsNotNone(user.last_login)

    def test_legacy_token_obtain_stamps(self):
        user = _user(username="legacy_stamper", password=_PW)
        with override_settings(
            STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True, "AUTH_LEGACY_TOKEN_LOGIN": True}
        ):
            resp = self.client.post(
                reverse("token_obtain_pair"),
                {"username": "legacy_stamper", "password": _PW},
            )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertIsNotNone(user.last_login)

    @patch("stapel_auth.otp.services.EmailVerificationService.verify_code")
    def test_email_otp_verify_stamps(self, mock_verify):
        mock_verify.return_value = {"success": True}
        user = _user(email="otpstamp@example.com")
        resp = self.client.post(
            reverse("email_verify"), {"email": "otpstamp@example.com", "code": "123456"}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertIsNotNone(user.last_login)

    @patch("stapel_auth.otp.services.PhoneVerificationService.verify_code")
    def test_phone_otp_verify_stamps(self, mock_verify):
        mock_verify.return_value = {"success": True}
        user = _user(phone="+79995550123", is_phone_verified=True, auth_type="phone")
        resp = self.client.post(
            reverse("phone_verify"), {"phone": "+79995550123", "code": "123456"}
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertIsNotNone(user.last_login)

    def test_qr_confirm_stamps_for_the_approving_account(self):
        """One of the two minters that legitimately bypasses the choke point:
        the scanner hands a *waiting device* a session on this account, so
        this account is logging in — elsewhere — right now."""
        user = _user(username="qr_stamper")
        client = _bearer_client_for(user)
        key = client.post(reverse("qr_generate"), {"type": "login_request"}).data["key"]
        resp = client.post(reverse("qr_confirm", kwargs={"key": key}))
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertIsNotNone(user.last_login)

    @patch("stapel_auth.otp.services.EmailVerificationService.verify_code")
    def test_guest_promotion_remint_stamps(self, mock_verify):
        """The other bypass: a guest session promoted mid-flow has all its
        sessions revoked and a fresh pair minted around the choke point."""
        mock_verify.return_value = {"success": True}
        user = User.create_anonymous_user()
        user.email = "gueststamp@example.com"
        user.is_email_verified = True
        user.save()
        client = _bearer_client_for(user)
        resp = client.post(
            reverse("password_change_otp_verify"),
            {"method": "email", "code": "123456", "new_password": "brandnew456!"},
        )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertIsNotNone(user.last_login)


@override_settings(STAPEL_AUTH={"AUTH_PASSWORD_LOGIN": True})
class PasswordLoginChallengeTests(APITestCase):
    """The stamp used to sit *before* the step-up branches in password login,
    so an account that got a TOTP challenge — and no session — was recorded
    as having logged in. It is stamped by the choke point now, which is
    downstream of every branch that can still turn the request away."""

    def test_totp_challenge_is_not_a_login(self):
        from stapel_auth.mfa.services import TOTPService

        user = _user(username="totp_challenged", password=_PW)
        with patch.object(TOTPService, "is_enabled", return_value=True):
            resp = self.client.post(
                reverse("password_login"),
                {"login": "totp_challenged", "password": _PW},
                format="json",
            )
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data["status"], "TOTP_REQUIRED")
        user.refresh_from_db()
        self.assertIsNone(user.last_login)

    def test_bad_password_is_not_a_login(self):
        user = _user(username="wrongpw", password=_PW)
        self.client.post(
            reverse("password_login"), {"login": "wrongpw", "password": "nope"}, format="json"
        )
        user.refresh_from_db()
        self.assertIsNone(user.last_login)


# =============================================================================
# Refresh is NOT a login
# =============================================================================


class RefreshDoesNotStampTests(APITestCase):
    def test_token_refresh_leaves_last_login_alone(self):
        user = _user(username="refresher")
        _, refresh = _issue_session_tokens(user, None, path=SessionPath.PASSWORD)
        user.refresh_from_db()
        first = user.last_login
        self.assertIsNotNone(first)

        # Move it far enough back that any re-stamp is unmistakable.
        stale = timezone.now() - datetime.timedelta(days=30)
        User.objects.filter(pk=user.pk).update(last_login=stale)

        resp = self.client.post(reverse("token_refresh"), {"refresh": refresh})
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        user.refresh_from_db()
        self.assertEqual(user.last_login, stale)


# =============================================================================
# The gate: no minter may hand out a session without stamping
# =============================================================================

#: Direct callers of ``create_tokens_for_user`` that mint no session and are
#: therefore not authentication sites — the TokenService facades. Mirrors
#: ``_BYPASS_ALLOWLIST`` in test_session_issuance_gate.py, which is the
#: roster this gate rides on: anything that IS a bypassing minter must stamp.
_NON_AUTHENTICATING_MINTERS = {
    "sessions/services.py::create_tokens_for_user",
    "sessions/services.py::get_refresh_token_for_user",
}

#: The choke point stamps for everyone who goes through it.
_CHOKE_POINT = "sessions/views.py::_issue_session_tokens"


def _minting_functions():
    """``file::function`` -> function source, for every direct minter."""
    found = {}
    for path in sorted(_REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(_REPO_ROOT)
        if rel.parts[0] in {"tests", "build", ".venv", "docs", "migrations"}:
            continue
        source = path.read_text()
        tree = ast.parse(source, filename=str(path))
        enclosing = {}
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(fn):
                    enclosing.setdefault(child, fn)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
            if name != "create_tokens_for_user":
                continue
            fn = enclosing.get(node)
            if fn is None:
                continue
            found[f"{rel}::{fn.name}"] = ast.get_source_segment(source, fn) or ""
    return found


class MinterStampGateTests(TestCase):
    """Turns "we remembered to stamp everywhere" into "the build fails when
    someone doesn't". Anyone minting a token pair outside the choke point is
    an authentication site unless it is a pure facade — and an authentication
    site that does not call ``stamp_last_login`` is the original defect,
    reopened."""

    def test_scan_finds_the_known_minters(self):
        # A gate that matches nothing passes vacuously; the floor exists only
        # so a broken scanner cannot be mistaken for a clean codebase.
        self.assertGreaterEqual(len(_minting_functions()), 4)

    def test_every_minter_stamps_or_is_a_declared_facade(self):
        unstamped = sorted(
            key
            for key, src in _minting_functions().items()
            if key != _CHOKE_POINT
            and key not in _NON_AUTHENTICATING_MINTERS
            and "stamp_last_login" not in src
        )
        self.assertEqual(
            unstamped,
            [],
            "these mint a session outside sessions.views._issue_session_tokens "
            "and never stamp last_login — either call stamp_last_login() or, "
            "if they really issue no session, declare them in "
            "_NON_AUTHENTICATING_MINTERS with a reason",
        )

    def test_the_choke_point_still_stamps(self):
        """Named explicitly: everything above leans on this one call, so its
        removal must break a test that says why, not just a subtest label."""
        self.assertIn("stamp_last_login", _minting_functions()[_CHOKE_POINT])

    def test_refresh_is_not_wired_to_the_stamp(self):
        """The exclusion is a decision, not an omission — pinned so it cannot
        be "fixed" by someone reading the refresh path in isolation."""
        source = (_REPO_ROOT / "sessions" / "views.py").read_text()
        tree = ast.parse(source)
        bodies = [
            ast.get_source_segment(source, node) or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name in {"_refresh_token", "refresh_post", "refresh_get"}
        ]
        self.assertTrue(bodies, "the refresh view moved — update this gate")
        for body in bodies:
            self.assertNotIn("stamp_last_login", body)


# =============================================================================
# The backfill migration
# =============================================================================


class _FakeSchemaEditor:
    """The two attributes ``backfill_last_login`` reads off it."""

    class _Conn:
        alias = "default"

    connection = _Conn()


#: The migration's name starts with a digit, so `import` cannot name it.
_MIGRATION = "stapel_auth.migrations.0020_backfill_last_login_from_audit_log"


def _migration_module():
    return import_module(_MIGRATION)


def _run_backfill():
    from django.apps import apps as global_apps

    _migration_module().backfill_last_login(global_apps, _FakeSchemaEditor())


def _audit(user, event_type, when):
    row = AuthAuditLog.objects.create(user=user, event_type=event_type)
    # created_at is auto_now_add — the only way to place a row in the past.
    AuthAuditLog.objects.filter(pk=row.pk).update(created_at=when)
    return row


class BackfillTests(TestCase):
    """The historical half: accounts that logged in before anything stamped.

    The evidence is ``auth_audit_log``, which got it right the whole time.
    """

    def setUp(self):
        self.now = timezone.now()

    def test_fills_a_null_from_the_latest_successful_login(self):
        user = _user()
        _audit(user, "login_success", self.now - datetime.timedelta(days=10))
        latest = self.now - datetime.timedelta(days=2)
        _audit(user, "login_success", latest)
        _audit(user, "login_success", self.now - datetime.timedelta(days=5))

        _run_backfill()

        user.refresh_from_db()
        self.assertEqual(user.last_login, latest)

    def test_leaves_a_non_null_alone(self):
        """Only NULLs. A value already there is at least as good as the audit
        log's, and overwriting could move a real timestamp backwards."""
        existing = self.now - datetime.timedelta(days=1)
        user = _user()
        User.objects.filter(pk=user.pk).update(last_login=existing)
        _audit(user, "login_success", self.now - datetime.timedelta(days=9))

        _run_backfill()

        user.refresh_from_db()
        self.assertEqual(user.last_login, existing)

    def test_user_with_no_login_event_stays_null(self):
        """NULL is the honest answer for "no evidence this account ever
        logged in" — inventing date_joined would turn a knowable gap into a
        plausible lie."""
        user = _user()
        _run_backfill()
        user.refresh_from_db()
        self.assertIsNone(user.last_login)

    def test_ignores_non_login_events(self):
        """A failed attempt, a logout, a password change and a revoked
        session are all things that are not a login."""
        user = _user()
        for event in (
            "login_failed",
            "logout",
            "password_changed",
            "session_revoked",
            "magic_link_sent",
            "totp_failed",
        ):
            _audit(user, event, self.now - datetime.timedelta(days=3))

        _run_backfill()

        user.refresh_from_db()
        self.assertIsNone(user.last_login)

    def test_every_successful_login_verb_counts(self):
        """The module wrote different verbs from different flows over its
        life; a backfill that only knew ``login_success`` would leave every
        SSO/OAuth/passkey-only account looking like it had never signed in."""
        SUCCESSFUL_LOGIN_EVENTS = _migration_module().SUCCESSFUL_LOGIN_EVENTS

        users = {}
        when = self.now - datetime.timedelta(days=4)
        for event in SUCCESSFUL_LOGIN_EVENTS:
            users[event] = _user()
            _audit(users[event], event, when)

        _run_backfill()

        for event, user in users.items():
            with self.subTest(event=event):
                user.refresh_from_db()
                self.assertEqual(user.last_login, when)

    def test_does_not_cross_users(self):
        loud, quiet = _user(), _user()
        when = self.now - datetime.timedelta(days=6)
        _audit(loud, "login_success", when)

        _run_backfill()

        loud.refresh_from_db()
        quiet.refresh_from_db()
        self.assertEqual(loud.last_login, when)
        self.assertIsNone(quiet.last_login)

    def test_is_idempotent(self):
        user = _user()
        when = self.now - datetime.timedelta(days=7)
        _audit(user, "login_success", when)

        _run_backfill()
        user.refresh_from_db()
        first = user.last_login

        _audit(user, "login_success", self.now)
        _run_backfill()
        user.refresh_from_db()
        self.assertEqual(
            user.last_login,
            first,
            "a second run must be a no-op — the row is no longer NULL",
        )

    def test_walks_past_a_full_batch(self):
        """Keyset pagination: the cursor has to advance across users that DO
        get filled and users that don't, or the walk stalls on the first page
        (or loops on it forever)."""
        from django.apps import apps as global_apps

        module = _migration_module()
        when = self.now - datetime.timedelta(days=8)
        with_event = [_user() for _ in range(3)]
        without_event = [_user() for _ in range(3)]
        for u in with_event:
            _audit(u, "login_success", when)

        with patch.object(module, "BATCH_SIZE", 2):
            module.backfill_last_login(global_apps, _FakeSchemaEditor())

        for u in with_event:
            u.refresh_from_db()
            self.assertEqual(u.last_login, when)
        for u in without_event:
            u.refresh_from_db()
            self.assertIsNone(u.last_login)

    def test_the_migration_hangs_off_the_tip_and_reverses_cleanly(self):
        """It must be reachable by ``migrate`` — chained to the current tip
        and to the swappable user model it writes to — and it must not claim
        to undo what it cannot: backwards is a no-op, because once written a
        backfilled stamp is indistinguishable from a real one.

        (The harness runs with ``MIGRATION_MODULES={"authentication": None}``,
        so there is no migration graph to load here; the file's own declared
        dependencies are the thing to check.)
        """
        migration = _migration_module().Migration
        deps = [tuple(d) for d in migration.dependencies]
        self.assertIn(("authentication", "0019_drop_verification_tables"), deps)
        self.assertTrue(
            [d for d in deps if d[1] == "__first__"],
            "no swappable_dependency on AUTH_USER_MODEL — the backfill writes "
            "to the user table and must be ordered after it exists",
        )
        self.assertEqual(len(migration.operations), 1)
        self.assertTrue(migration.operations[0].reversible)
