"""OAuth identities carry only addresses the provider verified.

* GitHub: the primary *verified* address from ``/user/emails`` — never the
  free-text public profile field, never a non-primary or unverified entry.
* Zoom: ``verified: 1`` on the user object, or the address is unverified.
* Matching an existing account is case-insensitive, and an address the
  provider did not verify is not stored on a new account at all (it would
  squat the mailbox's later email sign-in).
"""
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from stapel_core.oauth import OAuthUserData

from stapel_auth.oauth_providers import GitHubProvider, ZoomProvider
from stapel_auth.otp.views import AuthViewSet, OAuthEmailNotVerified
from stapel_auth.sessions.dto import AuthStatus

pytestmark = pytest.mark.django_db

User = get_user_model()


def _resp(status, payload):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload
    return r


def _github(profile, emails):
    def fake_get(url, **_):
        return _resp(200, emails if url.endswith("/user/emails") else profile)

    with patch("stapel_auth.oauth_providers.requests.get", side_effect=fake_get):
        return GitHubProvider().get_user_data("tok")


def test_github_ignores_the_public_profile_address():
    data = _github(
        {"id": 7, "login": "x", "email": "victim@example.com"},
        [
            {"email": "victim@example.com", "primary": False, "verified": True},
            {"email": "own@example.com", "primary": True, "verified": True},
        ],
    )
    assert data.email == "own@example.com"
    assert data.email_verified is True


def test_github_without_a_primary_verified_address_has_no_email():
    data = _github(
        {"id": 7, "login": "x", "email": None},
        [
            {"email": "victim@example.com", "primary": True, "verified": False},
            {"email": "other@example.com", "primary": False, "verified": True},
        ],
    )
    assert data.email is None
    assert data.email_verified is False


@pytest.mark.parametrize("flag,expected", [(1, True), (0, False), (None, False)])
def test_zoom_reports_its_own_verification_flag(flag, expected):
    payload = {"id": "z1", "email": "z@example.com", "first_name": "Z"}
    if flag is not None:
        payload["verified"] = flag
    with patch("stapel_auth.oauth_providers.requests.get", return_value=_resp(200, payload)):
        data = ZoomProvider().get_user_data("tok")
    assert data.email_verified is expected


def test_a_verified_address_matches_an_account_case_insensitively():
    account = User.objects.create(email="victim@example.com", is_email_verified=True)
    user, status = AuthViewSet()._resolve_oauth_user(
        "github",
        OAuthUserData(id="g1", email="Victim@Example.com", email_verified=True, username=None, avatar=None),
    )
    assert user.pk == account.pk
    assert status == AuthStatus.LOGGED_IN
    assert User.objects.filter(email__iexact="victim@example.com").count() == 1


def test_an_unverified_address_never_links_an_existing_account_in_any_case():
    User.objects.create(email="victim@example.com", is_email_verified=True)
    with pytest.raises(OAuthEmailNotVerified):
        AuthViewSet()._resolve_oauth_user(
            "zoom",
            OAuthUserData(id="z9", email="VICTIM@example.com", email_verified=False, username=None, avatar=None),
        )


def test_an_unverified_address_is_not_stored_on_a_new_account():
    user, status = AuthViewSet()._resolve_oauth_user(
        "zoom",
        OAuthUserData(id="z2", email="someone@example.com", email_verified=False, username=None, avatar=None),
    )
    assert status == AuthStatus.REGISTERED
    user.refresh_from_db()
    assert not user.email
    assert user.is_email_verified is False
