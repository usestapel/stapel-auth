"""The ad click that produced an account is stored on the account.

What these tests are actually defending. Offline conversion import is the
only reporting channel that survives the four ways this product's sign-up
breaks a browser session — a code read in a webmail tab, an OAuth round
trip, thirty minutes of thinking time, a visitor who never answered a
consent banner. It needs one thing the browser cannot supply later: the
click identifier, held server-side from the moment the account was born.

So the assertions here are about *when* a row exists, not about how it is
shaped:

* it exists when a call REGISTERED an account, on the OTP door and on the
  OAuth one;
* it does not exist when nobody sent one, and never appears by inference;
* it is not demoted by a stale replay, and is refreshed by a fresher click;
* a malformed object is refused loudly rather than dropped, because an
  attribution silently thrown away is a campaign silently reported as
  worthless;
* every platform the fleet actually buys traffic on can name its own
  identifier, and a channel that puts no identifier on the landing URL at
  all still attributes through ``utm.source`` — an accepted enum that is
  narrower than the ad accounts in use turns whole channels into "direct".
"""
import datetime
import uuid
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from stapel_auth.attribution import record_signup_attribution
from stapel_auth.models import SignupAttribution

User = get_user_model()

NOW = datetime.datetime(2026, 9, 5, 10, 11, 12, tzinfo=datetime.timezone.utc)
EARLIER = NOW - datetime.timedelta(days=3)
LATER = NOW + datetime.timedelta(days=3)


def _attribution(captured_at=NOW, click_id="EAIaIQobChMI-test", type_="gclid"):
    return {
        "click_id": click_id,
        "click_id_type": type_,
        "captured_at": captured_at.isoformat(),
        "utm": {"source": "google", "medium": "cpc", "campaign": "brand"},
    }


def _verify(client, email, body):
    """POST /email/verify/ with the code check stubbed.

    The suite's convention (tests/test_auth.py): the OTP itself is not what
    these tests are about, and stubbing it keeps the assertions on the
    attribution rather than on the code store's clock.
    """
    with patch(
        "stapel_auth.otp.services.EmailVerificationService.verify_code",
        return_value={"success": True},
    ):
        return client.post(
            reverse("email_verify"), {"email": email, **body}, format="json"
        )


@pytest.fixture
def client():
    cache.clear()
    return APIClient()


@pytest.mark.django_db
class TestOtpRegistration:
    """The OTP door — the one that answers ``status: REGISTERED``."""

    def test_a_registration_stores_the_click(self, client):
        email = f"{uuid.uuid4().hex}@example.com"

        response = _verify(
            client, email, {"code": "1234", "attribution": _attribution()}
        )
        assert response.status_code == 200, response.data
        assert response.data["status"] == "REGISTERED"

        row = SignupAttribution.objects.get(user__email=email)
        assert row.click_id == "EAIaIQobChMI-test"
        assert row.click_id_type == "gclid"
        assert row.captured_at == NOW
        assert row.utm_source == "google"
        assert row.utm_campaign == "brand"
        # Absent tags are stored blank, never null: "no term" and "we never
        # asked" are the same fact here and two spellings would be a lie.
        assert row.utm_term == ""

    def test_without_an_attribution_there_is_no_row(self, client):
        email = f"{uuid.uuid4().hex}@example.com"

        response = _verify(client, email, {"code": "1234"})
        assert response.status_code == 200, response.data
        assert response.data["status"] == "REGISTERED"
        assert not SignupAttribution.objects.filter(user__email=email).exists()

    def test_a_login_carries_no_new_attribution(self, client):
        """The second visit is not a second registration.

        A returning user's browser still holds the cookie from whatever ad
        brought them the first time. Writing it on every sign-in would
        re-date the account's origin to the most recent click and report
        the same person as a fresh conversion.
        """
        email = f"{uuid.uuid4().hex}@example.com"
        User.objects.create(email=email, auth_type="email", is_email_verified=True)

        response = _verify(
            client, email, {"code": "1234", "attribution": _attribution()}
        )
        assert response.status_code == 200, response.data
        assert response.data["status"] == "LOGGED_IN"
        assert not SignupAttribution.objects.filter(user__email=email).exists()

    def test_a_malformed_object_is_refused_with_the_fleet_envelope(self, client):
        email = f"{uuid.uuid4().hex}@example.com"

        response = _verify(
            client,
            email,
            {
                "code": "1234",
                # 'gclid_v2' is not an identifier any upload can name.
                "attribution": _attribution() | {"click_id_type": "gclid_v2"},
            },
        )
        assert response.status_code == 400
        assert response.data["localizable_error"] == "error.400.attribution_invalid"
        # Refused means refused: no half-registered account behind the 400.
        assert not User.objects.filter(email=email).exists()

    @pytest.mark.parametrize(
        "type_",
        # The Google three, unchanged, beside the three platforms 0.34.3
        # added. Parametrised rather than asserted as a set so a type that
        # passes validation but cannot be *stored* (a column too narrow, a
        # choice missing from the model) fails here and not in production.
        ["gclid", "gbraid", "wbraid", "yclid", "fbclid", "ttclid"],
    )
    def test_every_accepted_identifier_type_is_stored(self, client, type_):
        email = f"{uuid.uuid4().hex}@example.com"

        response = _verify(
            client,
            email,
            {"code": "1234", "attribution": _attribution(type_=type_)},
        )
        assert response.status_code == 200, response.data
        row = SignupAttribution.objects.get(user__email=email)
        assert row.click_id_type == type_
        assert row.click_id == "EAIaIQobChMI-test"

    def test_campaign_tags_alone_are_stored(self, client):
        """No click id on the landing URL is not "no attribution".

        An email campaign, a price aggregator, a paid placement that carries
        only utm_* — each brings a real visitor. Refusing the record because
        it has no click identifier reports every one of those accounts as
        direct traffic.
        """
        email = f"{uuid.uuid4().hex}@example.com"
        payload = {
            "captured_at": NOW.isoformat(),
            "utm": {"source": "newsletter", "medium": "email"},
        }

        response = _verify(client, email, {"code": "1234", "attribution": payload})
        assert response.status_code == 200, response.data

        row = SignupAttribution.objects.get(user__email=email)
        assert row.utm_source == "newsletter"
        assert row.utm_medium == "email"
        # Blank, never null: "this landing carried no click id" is a fact.
        assert row.click_id == ""
        assert row.click_id_type == ""

    def test_an_identifier_without_its_type_is_refused(self, client):
        """An offline upload names the field it posts to; this names none."""
        email = f"{uuid.uuid4().hex}@example.com"
        payload = _attribution()
        del payload["click_id_type"]

        response = _verify(client, email, {"code": "1234", "attribution": payload})
        assert response.status_code == 400
        assert response.data["localizable_error"] == "error.400.attribution_invalid"
        assert not User.objects.filter(email=email).exists()

    def test_a_type_naming_no_identifier_is_refused(self, client):
        """A platform label with nothing under it is not a record."""
        email = f"{uuid.uuid4().hex}@example.com"
        payload = _attribution(type_="yclid") | {"click_id": ""}

        response = _verify(client, email, {"code": "1234", "attribution": payload})
        assert response.status_code == 400
        assert response.data["localizable_error"] == "error.400.attribution_invalid"

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            # A timestamp and nothing to timestamp.
            {"captured_at": NOW.isoformat()},
            # utm present but naming no channel: the same emptiness, spelled
            # longer. utm.source is what makes a tag-only record readable.
            {"captured_at": NOW.isoformat(), "utm": {"medium": "cpc"}},
        ],
    )
    def test_an_empty_record_is_refused(self, client, payload):
        """The one attribution row per account must not be spent on nothing.

        An empty row is strictly worse than no row: "no row" is the honest
        answer to where an account came from, and a row that says nothing
        occupies the slot a later, real capture would have used.
        """
        email = f"{uuid.uuid4().hex}@example.com"

        response = _verify(client, email, {"code": "1234", "attribution": payload})
        assert response.status_code == 400
        assert response.data["localizable_error"] == "error.400.attribution_invalid"
        assert not SignupAttribution.objects.filter(user__email=email).exists()

    def test_unknown_keys_are_ignored(self, client):
        """A capture library that learns a new tag must not break sign-up."""
        email = f"{uuid.uuid4().hex}@example.com"

        payload = _attribution()
        payload["msclkid"] = "some-other-platform"
        payload["utm"]["id"] = "42"

        response = _verify(client, email, {"code": "1234", "attribution": payload})
        assert response.status_code == 200, response.data
        row = SignupAttribution.objects.get(user__email=email)
        assert row.click_id_type == "gclid"

    def test_the_axis_off_makes_the_field_a_no_op(self, client):
        """Off means "store nothing", not "refuse the request".

        A deployment that switches this off has a frontend already sending
        the object. Turning that into a 400 would take the sign-up down with
        the setting.
        """
        email = f"{uuid.uuid4().hex}@example.com"

        with override_settings(STAPEL_AUTH={"AUTH_SIGNUP_ATTRIBUTION": False}):
            response = _verify(
                client, email, {"code": "1234", "attribution": _attribution()}
            )
        assert response.status_code == 200, response.data
        assert response.data["status"] == "REGISTERED"
        assert not SignupAttribution.objects.filter(user__email=email).exists()


@pytest.mark.django_db
class TestOAuthRegistration:
    """The OAuth door — no request body, so the click rides the flow state."""

    EMAIL = "oauth-attr@example.com"

    def _provider_user(self, id="google-42", email=None, username="oauth-attr"):
        from stapel_core.oauth import OAuthUserData

        return OAuthUserData(
            id=id,
            email=email or self.EMAIL,
            username=username,
            avatar=None,
            email_verified=True,
        )

    def test_the_redirect_flow_carries_the_click_from_authorize_to_callback(
        self, client
    ):
        """The identifier is parked server-side, never handed to the provider."""
        with override_settings(
            STAPEL_AUTH={
                "OAUTH_PROVIDERS": {
                    "google": {"client_id": "cid", "client_secret": "secret"}
                }
            }
        ):
            authorize = client.get(
                reverse("oauth_authorize", kwargs={"provider": "google"}),
                {
                    "click_id": "EAIaIQobChMI-oauth",
                    "click_id_type": "wbraid",
                    "captured_at": NOW.isoformat(),
                    "utm_source": "google",
                },
            )
            assert authorize.status_code == 302
            state = authorize.url.split("state=")[1].split("&")[0]
            # The click never travels to the provider: only the opaque state
            # does, and the identifier waits on our side of the redirect.
            assert "EAIaIQobChMI-oauth" not in authorize.url

            with patch(
                "stapel_auth.oauth_providers.GoogleProvider.exchange_code",
                return_value="tok",
            ), patch(
                "stapel_auth.oauth.services.OAuthService.get_user_data",
                return_value=self._provider_user(),
            ):
                callback = client.get(
                    reverse("oauth_callback", kwargs={"provider": "google"}),
                    {"code": "authcode", "state": state},
                )
        assert callback.status_code in (200, 302), getattr(callback, "data", None)

        row = SignupAttribution.objects.get(user__email=self.EMAIL)
        assert row.click_id == "EAIaIQobChMI-oauth"
        assert row.click_id_type == "wbraid"
        assert row.utm_source == "google"

    def test_the_redirect_flow_carries_campaign_tags_with_no_click_id(
        self, client
    ):
        """The OAuth door is a registration door, and gets the same rule.

        A UTM-only landing that then signs in with Google would otherwise be
        the one shape the body doors accept and this one drops.
        """
        email = "oauth-utm-only@example.com"
        with override_settings(
            STAPEL_AUTH={
                "OAUTH_PROVIDERS": {
                    "google": {"client_id": "cid", "client_secret": "secret"}
                }
            }
        ):
            authorize = client.get(
                reverse("oauth_authorize", kwargs={"provider": "google"}),
                {
                    "captured_at": NOW.isoformat(),
                    "utm_source": "newsletter",
                    "utm_campaign": "autumn",
                },
            )
            assert authorize.status_code == 302
            state = authorize.url.split("state=")[1].split("&")[0]

            provider_user = self._provider_user(
                id="google-77", email=email, username="oauth-utm-only"
            )
            with patch(
                "stapel_auth.oauth_providers.GoogleProvider.exchange_code",
                return_value="tok",
            ), patch(
                "stapel_auth.oauth.services.OAuthService.get_user_data",
                return_value=provider_user,
            ):
                callback = client.get(
                    reverse("oauth_callback", kwargs={"provider": "google"}),
                    {"code": "authcode", "state": state},
                )
        assert callback.status_code in (200, 302), getattr(callback, "data", None)

        row = SignupAttribution.objects.get(user__email=email)
        assert row.click_id == ""
        assert row.click_id_type == ""
        assert row.utm_source == "newsletter"
        assert row.utm_campaign == "autumn"

    def test_a_navigation_with_no_tag_at_all_parks_nothing(self, client):
        """The ordinary sign-in: no advertising tag, no state entry, no row."""
        from stapel_auth.attribution import attribution_from_query

        assert attribution_from_query({}) is None
        assert attribution_from_query({"utm_medium": "cpc"}) is None

    def test_a_malformed_tag_does_not_take_the_sign_in_down(self, client):
        """A browser NAVIGATION is not a request body.

        The response to /authorize/ is a redirect to the provider's login
        screen. Answering a JSON 400 would put an error envelope in the
        address bar of somebody trying to sign in, and lose the whole
        sign-in over a marketing tag. So a bad tag is dropped and the
        redirect happens anyway — the opposite of what a body gets, on
        purpose.
        """
        with override_settings(
            STAPEL_AUTH={
                "OAUTH_PROVIDERS": {
                    "google": {"client_id": "cid", "client_secret": "secret"}
                }
            }
        ):
            authorize = client.get(
                reverse("oauth_authorize", kwargs={"provider": "google"}),
                {
                    "click_id": "EAIaIQobChMI-oauth",
                    "click_id_type": "not-a-real-type",
                    "captured_at": NOW.isoformat(),
                },
            )
        assert authorize.status_code == 302
        assert "accounts.google.com" in authorize.url


@pytest.mark.django_db
class TestCaptureOrdering:
    """Last click wins, and "last" is the clock, not the arrival order."""

    def _user(self):
        return User.objects.create(
            email=f"{uuid.uuid4().hex}@example.com", auth_type="email"
        )

    def _record(self, user, captured_at, click_id):
        from stapel_auth.attribution import parse_signup_attribution

        return record_signup_attribution(
            user,
            parse_signup_attribution(
                _attribution(captured_at=captured_at, click_id=click_id)
            ),
        )

    def test_an_older_capture_does_not_overwrite(self):
        user = self._user()
        self._record(user, NOW, "fresh")
        self._record(user, EARLIER, "stale")

        row = SignupAttribution.objects.get(user=user)
        assert row.click_id == "fresh"
        assert row.captured_at == NOW

    def test_a_newer_capture_does(self):
        user = self._user()
        self._record(user, NOW, "first")
        self._record(user, LATER, "second")

        row = SignupAttribution.objects.get(user=user)
        assert row.click_id == "second"
        assert row.captured_at == LATER

    def test_an_identical_capture_changes_nothing(self):
        """A replay of the same click is not new information."""
        user = self._user()
        self._record(user, NOW, "first")
        self._record(user, NOW, "replayed-with-a-different-id")

        assert SignupAttribution.objects.filter(user=user).count() == 1
        assert SignupAttribution.objects.get(user=user).click_id == "first"

    def test_nothing_to_store_is_not_an_error(self):
        assert record_signup_attribution(self._user(), None) is None


@pytest.mark.django_db
class TestCommFunction:
    """``auth.signup_attribution`` — the read side, for the uploader."""

    def test_it_answers_the_stored_row(self):
        from stapel_core.comm import call

        user = User.objects.create(
            email=f"{uuid.uuid4().hex}@example.com", auth_type="email"
        )
        SignupAttribution.objects.create(
            user=user,
            click_id="EAIaIQobChMI-comm",
            click_id_type="gbraid",
            captured_at=NOW,
            utm_campaign="brand",
        )

        answer = call("auth.signup_attribution", {"user_id": str(user.pk)})
        assert answer["user_id"] == str(user.pk)
        assert answer["click_id"] == "EAIaIQobChMI-comm"
        assert answer["click_id_type"] == "gbraid"
        assert answer["captured_at"] == NOW.isoformat()
        assert answer["utm"]["campaign"] == "brand"
        assert answer["utm"]["term"] == ""

    def test_a_tags_only_row_reads_back_with_a_blank_identifier(self):
        """The uploader has to be able to tell "nothing to upload" apart.

        A blank click_id on a row that exists means the channel is known and
        there is no offline conversion to post — a different fact from "no
        row", which means the account's origin was never captured at all.
        """
        from stapel_core.comm import call

        user = User.objects.create(
            email=f"{uuid.uuid4().hex}@example.com", auth_type="email"
        )
        SignupAttribution.objects.create(
            user=user,
            click_id="",
            click_id_type="",
            captured_at=NOW,
            utm_source="newsletter",
        )

        answer = call("auth.signup_attribution", {"user_id": str(user.pk)})
        assert answer["click_id"] == ""
        assert answer["click_id_type"] == ""
        assert answer["utm"]["source"] == "newsletter"

    def test_no_row_answers_none(self):
        """The ordinary answer, and it must not look like an outage."""
        from stapel_core.comm import call

        user = User.objects.create(
            email=f"{uuid.uuid4().hex}@example.com", auth_type="email"
        )
        assert call("auth.signup_attribution", {"user_id": str(user.pk)}) is None

    def test_an_unparseable_id_answers_none_too(self):
        from stapel_core.comm import call

        assert call("auth.signup_attribution", {"user_id": "not-an-id"}) is None
