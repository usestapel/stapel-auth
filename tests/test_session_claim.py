"""Access and refresh tokens carry the id of their session (``sid``).

A service in another process (the push device registry, audit) reads the
caller's session off the verified token — ``stapel_core.django.jwt.claims.
request_session_id`` — instead of trusting a client-sent id or reaching into
this module's tables. These tests hold the issuer's half:

* every pair minted for a session row carries that row's id, on every path:
  the choke point (all sign-in methods and guests), the pairs minted around it
  (QR login request, guest promotion), refresh rotation, the grace answer and
  core's mint-from-refresh;
* a pair minted before the claim existed keeps working, and gains the claim on
  its first rotation;
* the roster: every call that mints a pair names its session, or says why it
  has none.
"""
import ast
import uuid
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase
from stapel_core.core.jwt_handler import SESSION_CLAIM
from stapel_core.django.jwt.provider import jwt_provider

from stapel_auth.models import UserSession
from stapel_auth.sessions.guard import SessionPath
from stapel_auth.sessions.services import SessionService, current_session
from stapel_auth.sessions.views import _issue_session_tokens

User = get_user_model()

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _user():
    return User.objects.create_user(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )


def _claims(token):
    return jwt_provider.handler.decode_token(token, verify=False) or {}


def _sid(token):
    return _claims(token).get(SESSION_CLAIM)


def _legacy_pair(user):
    """A pair as issued before the claim existed: no ``sid``."""
    from stapel_core.django.jwt.utils import serialize_user_to_jwt_data

    access, refresh = jwt_provider.create_tokens_from_data(serialize_user_to_jwt_data(user))
    assert SESSION_CLAIM not in _claims(access)
    return access, refresh


def _bearer_request(token, user):
    request = RequestFactory().get("/x/", HTTP_AUTHORIZATION=f"Bearer {token}")
    request.user = user
    return request


@override_settings(URL_PREFIX="", JWT_REFRESH_ALLOWED=True, STAPEL_AUTH={"REFRESH_ROTATION_GRACE_SECONDS": 10})
class PairsCarryTheirSession(APITestCase):
    def setUp(self):
        cache.clear()
        self.user = _user()

    def _issue(self, path=SessionPath.PASSWORD):
        access, refresh = _issue_session_tokens(self.user, None, path=path)
        session = UserSession.objects.get(jti=_claims(refresh)["jti"])
        return access, refresh, session

    def test_choke_point_pair_names_its_session_row(self):
        access, refresh, session = self._issue()
        self.assertEqual(_sid(access), str(session.pk))
        self.assertEqual(_sid(refresh), str(session.pk))
        self.assertEqual(jwt_provider.validate_token(access)[SESSION_CLAIM], str(session.pk))

    def test_two_sign_ins_two_sessions(self):
        first, _, s1 = self._issue()
        second, _, s2 = self._issue(SessionPath.OTP_EMAIL)
        self.assertNotEqual(s1.pk, s2.pk)
        self.assertEqual({_sid(first), _sid(second)}, {str(s1.pk), str(s2.pk)})

    def test_guest_session_carries_the_claim(self):
        response = APIClient().post(reverse("anonymous"), {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.content)
        access = response.data["tokens"]["access"]
        guest = User.objects.get(pk=response.data["user"]["id"])
        session = UserSession.objects.get(user=guest)
        self.assertEqual(_sid(access), str(session.pk))
        self.assertEqual(_sid(response.data["tokens"]["refresh"]), str(session.pk))

    def test_refresh_rotation_keeps_the_session(self):
        _, refresh, session = self._issue()
        rotated = self.client.post(reverse("token_refresh"), {"refresh": refresh})
        self.assertEqual(rotated.status_code, 200)
        self.assertEqual(_sid(rotated.data["access"]), str(session.pk))
        self.assertEqual(_sid(rotated.data["refresh"]), str(session.pk))

    def test_grace_answer_keeps_the_session(self):
        _, refresh, session = self._issue()
        self.client.post(reverse("token_refresh"), {"refresh": refresh})
        raced = self.client.post(reverse("token_refresh"), {"refresh": refresh})
        self.assertEqual(raced.status_code, 200)
        self.assertEqual(_sid(raced.data["access"]), str(session.pk))

    def test_core_mint_from_refresh_keeps_the_session(self):
        _, refresh, session = self._issue()
        minted = jwt_provider.refresh_access_token(refresh)
        self.assertEqual(_sid(minted), str(session.pk))

    def test_pair_registered_outside_the_gate_gets_its_claimed_id(self):
        """Guest promotion and the QR poll mint first and register the row
        after; the row takes the id the pair already carries."""
        from stapel_auth.sessions.services import new_session_id
        from stapel_auth.staff_roles import create_tokens_for_user

        sid = new_session_id()
        access, refresh = create_tokens_for_user(self.user, session_id=sid)
        session = SessionService.create_for_pair(self.user, access, refresh)
        self.assertEqual(session.pk, sid)

    def test_qr_login_request_pair_names_the_polling_devices_session(self):
        scanner_access, _, _ = self._issue()
        poller = APIClient()  # the waiting device; it holds the poll nonce
        key = poller.post(reverse("qr_generate"), {"type": "login_request"}).data["key"]
        confirmer = APIClient()
        confirmer.credentials(HTTP_AUTHORIZATION=f"Bearer {scanner_access}")
        self.assertEqual(confirmer.post(reverse("qr_confirm", kwargs={"key": key})).status_code, 200)
        polled = poller.get(reverse("qr_status", kwargs={"key": key}))
        self.assertEqual(polled.data["status"], "fulfilled")
        session = UserSession.objects.get(jti=_claims(polled.data["refresh_token"])["jti"])
        self.assertEqual(_sid(polled.data["access_token"]), str(session.pk))


@override_settings(URL_PREFIX="", JWT_REFRESH_ALLOWED=True)
class TokensFromBeforeTheClaim(APITestCase):
    """Issued by an older release: no ``sid``. They keep working."""

    def setUp(self):
        cache.clear()
        self.user = _user()
        self.access, self.refresh = _legacy_pair(self.user)
        self.session = SessionService.create(
            self.user, _claims(self.refresh)["jti"],
            jwt_provider.handler.get_token_expiration(self.refresh),
            access_token=self.access,
        )

    def test_old_access_token_authenticates_and_finds_its_session(self):
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.access}")
        listed = self.client.get(reverse("sessions"))
        self.assertEqual(listed.status_code, 200)
        current = [s["id"] for s in listed.data if s["is_current"]]
        self.assertEqual(current, [str(self.session.pk)])

    def test_first_rotation_adds_the_claim(self):
        rotated = self.client.post(reverse("token_refresh"), {"refresh": self.refresh})
        self.assertEqual(rotated.status_code, 200)
        self.assertEqual(_sid(rotated.data["access"]), str(self.session.pk))
        self.assertEqual(_sid(rotated.data["refresh"]), str(self.session.pk))

    def test_core_mint_from_an_old_refresh_token_has_no_claim(self):
        minted = jwt_provider.refresh_access_token(self.refresh)
        self.assertIsNotNone(minted)
        self.assertNotIn(SESSION_CLAIM, _claims(minted))


class CurrentSessionReadsTheClaim(TestCase):
    def setUp(self):
        cache.clear()
        self.user = _user()

    def test_claim_names_the_session(self):
        access, refresh = _issue_session_tokens(self.user, None, path=SessionPath.PASSWORD)
        session = UserSession.objects.get(jti=_claims(refresh)["jti"])
        # The ledger is not consulted: emptied, the claim alone finds it.
        session.access_tokens.all().delete()
        UserSession.objects.filter(pk=session.pk).update(access_jti="")
        self.assertEqual(current_session(_bearer_request(access, self.user)), session)

    def test_claim_naming_another_users_session_is_not_followed(self):
        """A validly signed sid can only select among the caller's own rows."""
        from stapel_auth.staff_roles import create_tokens_for_user

        victim = _user()
        _, victim_refresh = _issue_session_tokens(victim, None, path=SessionPath.PASSWORD)
        victim_session = UserSession.objects.get(jti=_claims(victim_refresh)["jti"])
        access, _ = create_tokens_for_user(self.user, session_id=victim_session.pk)
        self.assertIsNone(current_session(_bearer_request(access, self.user)))

    def test_claim_naming_no_row_falls_back_to_the_ledger(self):
        from stapel_auth.staff_roles import create_tokens_for_user

        access, refresh = create_tokens_for_user(self.user, session_id=uuid.uuid4())
        session = SessionService.create(
            self.user, _claims(refresh)["jti"],
            jwt_provider.handler.get_token_expiration(refresh),
            access_token=access, session_id=uuid.uuid4(),
        )
        self.assertEqual(current_session(_bearer_request(access, self.user)), session)


# =============================================================================
# Roster: every pair minted in this package names its session, or says why not
# =============================================================================

#: ``create_tokens_for_user`` callers that mint WITHOUT ``session_id=``, and why.
_NO_SESSION = {
    "sessions/services.py::create_tokens_for_user": "TokenService facade; mints no session row",
    "sessions/services.py::get_refresh_token_for_user": "TokenService facade; mints no session row",
}


def _mint_calls():
    calls = []
    for path in sorted(_REPO_ROOT.rglob("*.py")):
        rel = path.relative_to(_REPO_ROOT)
        if rel.parts[0] in {"tests", "build", ".venv", "docs"}:
            continue
        tree = ast.parse(path.read_text(), filename=str(path))
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
            names_session = any(kw.arg == "session_id" for kw in node.keywords)
            calls.append((f"{rel}::{enclosing.get(node, '<module>')}", node.lineno, names_session))
    return calls


class EveryPairNamesItsSession(TestCase):
    def test_scan_finds_the_known_callers(self):
        self.assertGreaterEqual(len(_mint_calls()), 5)

    def test_every_mint_names_its_session_or_is_on_the_roster(self):
        unnamed = sorted(
            f"{key} (line {line})"
            for key, line, names_session in _mint_calls()
            if not names_session and key not in _NO_SESSION
        )
        self.assertEqual(
            unnamed, [],
            "a token pair is minted without session_id=: name the session the "
            "pair belongs to (sessions.services.new_session_id) or add the call "
            "to _NO_SESSION with the reason it has none",
        )
