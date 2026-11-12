"""Every access token is recorded on its session, so a per-device revoke kills
it at once — whichever path minted it.

Two genres, as in ``test_session_issuance_gate``:

* behaviour: each mint path hands out a real token; its jti must be a
  ``SessionAccessToken`` row of the right session, and after the session is
  revoked ``jwt_provider.validate_token`` must refuse it (not "until expiry");
* roster: an AST scan of the package for every call that mints an access
  token. Each call site must be on :data:`_MINT_SITES` with how its token
  reaches ``SessionService.record_access`` (or why it has no session). A new
  mint path fails the build until somebody writes that down.
"""
import ast
import uuid
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APITestCase
from stapel_core.django.jwt.provider import jwt_provider

from stapel_auth.models import SessionAccessToken, UserSession
from stapel_auth.sessions.guard import SessionPath
from stapel_auth.sessions.services import SessionService
from stapel_auth.sessions.views import _issue_session_tokens

User = get_user_model()

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _user():
    return User.objects.create_user(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )


def _jti(token):
    return (jwt_provider.handler.decode_token(token, verify=False) or {}).get("jti")


class _Assertions:
    def assertRecordedOn(self, access, session):
        self.assertTrue(
            SessionAccessToken.objects.filter(jti=_jti(access), session=session).exists(),
            "an access token was handed out that its session does not know about",
        )

    def assertAlive(self, access):
        self.assertIsNotNone(jwt_provider.validate_token(access))

    def assertDead(self, access):
        self.assertIsNone(
            jwt_provider.validate_token(access),
            "the access token survived the revocation of its session",
        )


@override_settings(URL_PREFIX="", JWT_REFRESH_ALLOWED=True, STAPEL_AUTH={"REFRESH_ROTATION_GRACE_SECONDS": 10})
class EveryMintPathIsRecordedAndRevocable(_Assertions, APITestCase):
    def setUp(self):
        cache.clear()
        self.user = _user()
        self.access, self.refresh = _issue_session_tokens(
            self.user, None, path=SessionPath.PASSWORD
        )
        self.session = UserSession.objects.get(jti=_jti(self.refresh))

    def _revoke(self):
        SessionService.revoke_session(UserSession.objects.get(pk=self.session.pk))

    def test_login(self):
        self.assertRecordedOn(self.access, self.session)
        self.assertAlive(self.access)
        self._revoke()
        self.assertDead(self.access)

    def test_refresh_rotation_kills_the_old_and_the_new_access_token(self):
        rotated = self.client.post(reverse("token_refresh"), {"refresh": self.refresh})
        self.assertEqual(rotated.status_code, 200)
        new_access = rotated.data["access"]
        self.assertRecordedOn(new_access, self.session)
        self.assertRecordedOn(self.access, self.session)
        self._revoke()
        self.assertDead(new_access)
        self.assertDead(self.access)

    def test_rotation_grace_answer(self):
        won = self.client.post(reverse("token_refresh"), {"refresh": self.refresh})
        raced = self.client.post(reverse("token_refresh"), {"refresh": self.refresh})
        self.assertEqual(raced.status_code, 200)
        self.assertNotEqual(raced.data["access"], won.data["access"])
        self.assertRecordedOn(raced.data["access"], self.session)
        self._revoke()
        for access in (self.access, won.data["access"], raced.data["access"]):
            self.assertDead(access)

    def test_core_mint_from_refresh(self):
        """The provider call the JWT middleware, channels and core's refresh
        view share — the path that minted unrecorded tokens."""
        minted = jwt_provider.refresh_access_token(self.refresh)
        self.assertIsNotNone(minted)
        self.assertRecordedOn(minted, self.session)
        self._revoke()
        self.assertDead(minted)

    def test_middleware_refresh_of_an_expired_access_cookie(self):
        from django.contrib.sessions.backends.cache import SessionStore
        from stapel_core.django.jwt.middleware import JWTAuthMiddleware
        from stapel_core.django.jwt.utils import jwt_cookie_names

        _access_name, refresh_name = jwt_cookie_names()
        request = RequestFactory().get("/auth/api/v1/me/")
        request.COOKIES = {refresh_name: self.refresh}
        request.session = SessionStore()
        JWTAuthMiddleware(lambda r: HttpResponse()).process_request(request)
        minted = request._new_access_token
        self.assertRecordedOn(minted, self.session)
        self._revoke()
        self.assertDead(minted)

    def test_per_device_revoke_over_http(self):
        """The surface the user presses: another device revokes this one."""
        other_access, _ = _issue_session_tokens(self.user, None, path=SessionPath.PASSWORD)
        minted = jwt_provider.refresh_access_token(self.refresh)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {other_access}")
        response = self.client.delete(
            reverse("session_revoke", args=[str(self.session.pk)])
        )
        self.assertEqual(response.status_code, 200)
        self.assertDead(self.access)
        self.assertDead(minted)
        self.assertAlive(other_access)

    def test_session_for_a_pair_minted_outside_the_gate(self):
        """Guest promotion (password/views.py) and QR poll register the pair."""
        from stapel_auth.staff_roles import create_tokens_for_user

        access, refresh = create_tokens_for_user(self.user)
        session = SessionService.create_for_pair(self.user, access, refresh)
        self.assertRecordedOn(access, session)
        SessionService.revoke_session(session)
        self.assertDead(access)

    def test_a_mint_that_races_the_revocation_is_blacklisted_on_record(self):
        self._revoke()
        from stapel_auth.staff_roles import create_tokens_for_user

        late, _ = create_tokens_for_user(self.user)
        SessionService.record_access(UserSession.objects.get(pk=self.session.pk), late)
        self.assertDead(late)

    def test_revoke_all_reaches_every_recorded_access_token(self):
        minted = jwt_provider.refresh_access_token(self.refresh)
        SessionService.revoke_all(self.user)
        self.assertDead(self.access)
        self.assertDead(minted)


# =============================================================================
# The roster: every call in this package that mints an access token
# =============================================================================

#: Names whose call mints an access token (alone or in a pair).
_MINTERS = {
    "create_tokens_for_user",
    "create_tokens_from_data",
    "create_tokens",
    "refresh_access_token",
    "create_access_token",
    "generate_access_token",
    "generate_token_pair",
}

#: ``file::enclosing function`` -> how the minted access token reaches
#: ``SessionService.record_access`` (or why it belongs to no session).
_MINT_SITES = {
    "staff_roles.py::create_tokens_for_user": (
        "the primitive itself; every caller is on this roster"
    ),
    "sessions/views.py::_issue_session_tokens": "SessionService.create(access_token=...)",
    "sessions/views.py::_grace_pair_response": (
        "SessionService.record_access(graced, ...) and the core access observer"
    ),
    "sessions/views.py::_refresh_token": (
        "rotation: SessionService.rotate(new_access_token=...); the legacy "
        "no-jti branch has no session and is refused unless "
        "ALLOW_UNTRACKED_REFRESH; its provider call goes through the core "
        "access observer"
    ),
    "password/views.py::change_otp_verify": "SessionService.create_for_pair",
    "qr/views.py::confirm": (
        "pair parked for the polling device; recorded by SessionService.create("
        "access_token=...) when the poll collects it (qr/views.py::poll)"
    ),
    "mfa/views.py::exchange": (
        "enroll-only access token with no refresh token and no session: it "
        "authorises MFA enrolment alone (DenyEnrollOnly) and is not a device "
        "session a user could revoke"
    ),
    "sessions/services.py::create_tokens_for_user": (
        "TokenService facade: mints no session row (sessionless pair; a "
        "consumer that hands it out registers it with create_for_pair)"
    ),
    "sessions/services.py::get_refresh_token_for_user": "TokenService facade, same",
}


def _mint_call_sites():
    sites = []
    for path in sorted(_REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(_REPO_ROOT)
        if rel.parts[0] in {"tests", "build", ".venv", "docs", "migrations"}:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
        enclosing = {}
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for child in ast.walk(fn):
                    enclosing[child] = fn.name  # innermost wins (walk is outer-first)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            name = f.id if isinstance(f, ast.Name) else getattr(f, "attr", None)
            if name in _MINTERS:
                sites.append((f"{rel}::{enclosing.get(node, '<module>')}", node.lineno))
    return sites


class MintCallSiteRosterTests(TestCase):
    """Bounded by: calls spelled with one of :data:`_MINTERS` in this package's
    own source. A mint through an alias or in another package is not seen
    here; core's mint-from-refresh is covered by the observer test above."""

    def test_the_scan_sees_the_known_minters(self):
        found = {key for key, _ in _mint_call_sites()}
        self.assertGreaterEqual(len(found), 6, found)
        self.assertIn("sessions/views.py::_issue_session_tokens", found)

    def test_every_mint_call_site_is_accounted_for(self):
        unaccounted = sorted(
            f"{key} (line {line})"
            for key, line in _mint_call_sites()
            if key not in _MINT_SITES
        )
        self.assertEqual(
            unaccounted, [],
            "new access-token mint path(s): route the token through "
            "SessionService.record_access (or create/create_for_pair/rotate) "
            "and add the call site to _MINT_SITES with how it is recorded",
        )

    def test_no_stale_roster_entries(self):
        found = {key for key, _ in _mint_call_sites()}
        self.assertEqual(sorted(set(_MINT_SITES) - found), [])
