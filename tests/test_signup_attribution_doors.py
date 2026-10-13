"""Every door that can create an account keeps where it came from.

One claim per door, in two halves: a record carrying only campaign tags
(plus the landing surface) lands, and a malformed record never costs the
account. The doors: e-mail OTP, phone OTP, OAuth by token, OAuth by
redirect, the guest mint, and the guest becoming an account — in place or
by merging into an account that already existed.
"""
import datetime
import uuid
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from stapel_auth.attribution import (
    attribution_from_query,
    parse_signup_attribution,
    record_signup_attribution,
)
from stapel_auth.models import SignupAttribution
from stapel_auth.otp.services import merge_anonymous_into

User = get_user_model()

NOW = datetime.datetime(2026, 9, 5, 10, 11, 12, tzinfo=datetime.timezone.utc)
EARLIER = NOW - datetime.timedelta(days=3)
LATER = NOW + datetime.timedelta(days=3)

UTM_ONLY = {
    "captured_at": NOW.isoformat(),
    "utm": {"source": "newsletter", "medium": "email", "campaign": "autumn"},
    "landing_ref": "pricing_hero",
}
MALFORMED = {"click_id": "abc", "click_id_type": "not-a-platform"}

GOOGLE = {"OAUTH_PROVIDERS": {"google": {"client_id": "cid", "client_secret": "s"}}}


@pytest.fixture
def client():
    cache.clear()
    return APIClient()


def _email():
    return f"{uuid.uuid4().hex}@example.com"


def _assert_utm_only_row(user):
    row = SignupAttribution.objects.get(user=user)
    assert row.utm_source == "newsletter"
    assert row.utm_campaign == "autumn"
    assert row.landing_ref == "pricing_hero"
    assert row.click_id == ""
    return row


def _email_verify(client, email, attribution):
    with patch(
        "stapel_auth.otp.services.EmailVerificationService.verify_code",
        return_value={"success": True},
    ):
        return client.post(
            reverse("email_verify"),
            {"email": email, "code": "1234", "attribution": attribution},
            format="json",
        )


def _phone_verify(client, phone, attribution):
    with patch(
        "stapel_auth.otp.services.PhoneVerificationService.verify_code",
        return_value={"success": True},
    ):
        return client.post(
            reverse("phone_verify"),
            {"phone": phone, "code": "1234", "attribution": attribution},
            format="json",
        )


def _provider_user(email):
    from stapel_core.oauth import OAuthUserData

    return OAuthUserData(
        id=f"google-{uuid.uuid4().hex}",
        email=email,
        username=email.split("@")[0][:20],
        avatar=None,
        email_verified=True,
    )


def _oauth_login(client, email, attribution):
    with patch(
        "stapel_auth.oauth.services.OAuthService.get_user_data",
        return_value=_provider_user(email),
    ):
        return client.post(
            reverse("oauth_login"),
            {"provider": "google", "access_token": "tok", "attribution": attribution},
            format="json",
        )


def _oauth_redirect(client, email, query):
    with override_settings(STAPEL_AUTH=GOOGLE):
        authorize = client.get(
            reverse("oauth_authorize", kwargs={"provider": "google"}), query
        )
        assert authorize.status_code == 302
        state = authorize.url.split("state=")[1].split("&")[0]
        with patch(
            "stapel_auth.oauth_providers.GoogleProvider.exchange_code",
            return_value="tok",
        ), patch(
            "stapel_auth.oauth.services.OAuthService.get_user_data",
            return_value=_provider_user(email),
        ):
            return client.get(
                reverse("oauth_callback", kwargs={"provider": "google"}),
                {"code": "authcode", "state": state},
            )


def _mint_guest(client, body):
    response = client.post(reverse("anonymous"), body, format="json")
    assert response.status_code == 201, response.data
    return User.objects.get(pk=response.data["user"]["id"]), response


def _as_guest(response):
    guest_client = APIClient()
    guest_client.credentials(
        HTTP_AUTHORIZATION=f"Bearer {response.data['tokens']['access']}"
    )
    return guest_client


@pytest.mark.django_db
class TestEmailOtpDoor:
    def test_a_utm_only_record_lands(self, client):
        email = _email()
        response = _email_verify(client, email, UTM_ONLY)
        assert response.status_code == 200, response.data
        _assert_utm_only_row(User.objects.get(email=email))


@pytest.mark.django_db
class TestPhoneOtpDoor:
    def test_a_utm_only_record_lands(self, client):
        response = _phone_verify(client, "+12025550142", UTM_ONLY)
        assert response.status_code == 200, response.data
        assert response.data["status"] == "REGISTERED"
        _assert_utm_only_row(User.objects.get(phone="+12025550142"))

    def test_a_malformed_record_never_fails_the_sign_up(self, client):
        response = _phone_verify(client, "+12025550143", MALFORMED)
        assert response.status_code == 200, response.data
        assert response.data["status"] == "REGISTERED"
        user = User.objects.get(phone="+12025550143")
        assert not SignupAttribution.objects.filter(user=user).exists()


@pytest.mark.django_db
class TestOAuthTokenDoor:
    def test_a_utm_only_record_lands(self, client):
        email = _email()
        response = _oauth_login(client, email, UTM_ONLY)
        assert response.status_code == 200, response.data
        _assert_utm_only_row(User.objects.get(email=email))

    @pytest.mark.parametrize("attribution", [MALFORMED, "not-an-object", [1, 2]])
    def test_a_malformed_record_never_fails_the_sign_up(self, client, attribution):
        email = _email()
        response = _oauth_login(client, email, attribution)
        assert response.status_code == 200, response.data
        assert response.data["status"] == "REGISTERED"
        assert not SignupAttribution.objects.filter(user__email=email).exists()


@pytest.mark.django_db
class TestOAuthRedirectDoor:
    def test_bare_keys_without_a_capture_time_land(self, client):
        """The shape a landing link actually carries: bare names, no clock."""
        email = _email()
        before = timezone.now()
        callback = _oauth_redirect(
            client,
            email,
            {"source": "newsletter", "campaign": "autumn", "ref": "pricing_hero"},
        )
        assert callback.status_code in (200, 302)
        row = _assert_utm_only_row(User.objects.get(email=email))
        assert before <= row.captured_at <= timezone.now()

    # A malformed query is dropped at /authorize/: see
    # test_signup_attribution.py::TestOAuthRegistration.


@pytest.mark.django_db
class TestGuestDoor:
    def test_a_utm_only_record_lands_on_the_guest(self, client):
        guest, _ = _mint_guest(client, {"attribution": UTM_ONLY})
        assert guest.is_anonymous
        _assert_utm_only_row(guest)

    def test_a_malformed_record_never_fails_guest_creation(self, client, caplog):
        with caplog.at_level("WARNING", logger="stapel_auth.attribution"):
            guest, _ = _mint_guest(client, {"attribution": MALFORMED})
        assert not SignupAttribution.objects.filter(user=guest).exists()
        assert any("malformed" in r.getMessage() for r in caplog.records)

    def test_a_reused_guest_session_records_nothing_new(self, client):
        guest, response = _mint_guest(client, {"attribution": UTM_ONLY})
        later = UTM_ONLY | {
            "captured_at": LATER.isoformat(),
            "utm": {"source": "replayed"},
        }
        again, _ = _mint_guest(_as_guest(response), {"attribution": later})
        assert again.pk == guest.pk
        _assert_utm_only_row(guest)


@pytest.mark.django_db
class TestGuestBecomesAnAccount:
    def test_promotion_keeps_the_guest_record(self, client):
        guest, response = _mint_guest(client, {"attribution": UTM_ONLY})
        email = _email()
        verify = _email_verify(_as_guest(response), email, None)
        assert verify.status_code == 200, verify.data
        assert verify.data["status"] == "REGISTERED"
        promoted = User.objects.get(email=email)
        assert promoted.pk == guest.pk
        _assert_utm_only_row(promoted)

    def test_a_merge_carries_the_guest_record_to_the_account(self, client):
        email = _email()
        existing = User.objects.create(
            email=email, auth_type="email", is_email_verified=True
        )
        guest, response = _mint_guest(client, {"attribution": UTM_ONLY})
        verify = _email_verify(_as_guest(response), email, None)
        assert verify.status_code == 200, verify.data
        assert verify.data["status"] == "MERGED"
        assert not User.objects.filter(pk=guest.pk).exists()
        _assert_utm_only_row(existing)

    def test_a_malformed_record_never_fails_the_merge(self, client):
        email = _email()
        User.objects.create(email=email, auth_type="email", is_email_verified=True)
        _, response = _mint_guest(client, {"attribution": MALFORMED})
        verify = _email_verify(_as_guest(response), email, MALFORMED)
        assert verify.status_code == 200, verify.data
        assert verify.data["status"] == "MERGED"


@pytest.mark.django_db
class TestMergeOrdering:
    """The merge obeys the same rule as a write: the newer capture wins."""

    def _pair(self, guest_at, survivor_at):
        survivor = User.objects.create(email=_email(), auth_type="email")
        guest = User.create_anonymous_user()
        record_signup_attribution(
            guest,
            parse_signup_attribution(
                {"captured_at": guest_at.isoformat(), "utm": {"source": "guest"}}
            ),
        )
        if survivor_at is not None:
            record_signup_attribution(
                survivor,
                parse_signup_attribution(
                    {
                        "captured_at": survivor_at.isoformat(),
                        "utm": {"source": "survivor"},
                    }
                ),
            )
        merge_anonymous_into(guest.pk, survivor)
        return SignupAttribution.objects.get(user=survivor)

    def test_the_newer_capture_wins_in_both_directions(self):
        newer_guest = self._pair(guest_at=LATER, survivor_at=NOW)
        assert newer_guest.utm_source == "guest"
        assert newer_guest.captured_at == LATER

        newer_survivor = self._pair(guest_at=EARLIER, survivor_at=NOW)
        assert newer_survivor.utm_source == "survivor"
        assert newer_survivor.captured_at == NOW


class TestTolerantQuery:
    """U2: the query is a navigation, read the way landings actually write it."""

    def test_bare_keys_map_to_the_campaign_tags_and_utm_wins(self):
        value = attribution_from_query(
            {
                "source": "bare-loses",
                "utm_source": "newsletter",
                "medium": "email",
                "campaign": "autumn",
                "term": "notes",
                "content": "banner",
                "captured_at": NOW.isoformat(),
            }
        )
        assert value["utm"] == {
            "source": "newsletter",
            "medium": "email",
            "campaign": "autumn",
            "term": "notes",
            "content": "banner",
        }

    def test_a_missing_capture_time_is_now(self):
        before = timezone.now()
        value = attribution_from_query({"utm_source": "newsletter"})
        assert before <= value["captured_at"] <= timezone.now()

    def test_ref_is_read_as_the_landing_surface(self):
        value = attribution_from_query({"ref": "header_mobile_cta"})
        assert value["landing_ref"] == "header_mobile_cta"
        assert not value.get("utm")


class TestLandingRef:
    """U3: a short slug, and a bad one costs only itself."""

    def _parse(self, landing_ref):
        return parse_signup_attribution(
            {
                "captured_at": NOW.isoformat(),
                "utm": {"source": "newsletter"},
                "landing_ref": landing_ref,
            }
        )

    def test_a_slug_is_kept(self):
        assert self._parse("transcribe_hero")["landing_ref"] == "transcribe_hero"

    @pytest.mark.parametrize(
        "landing_ref",
        ["Header_CTA", "with-dash", "a" * 65, "space here", 42, "<script>"],
    )
    def test_an_invalid_ref_is_dropped_and_the_record_kept(self, landing_ref, caplog):
        with caplog.at_level("WARNING", logger="stapel_auth.attribution"):
            value = self._parse(landing_ref)
        assert value["landing_ref"] == ""
        assert value["utm"]["source"] == "newsletter"
        assert any("landing_ref" in r.getMessage() for r in caplog.records)

    def test_the_longest_slug_is_kept(self):
        assert self._parse("a" * 64)["landing_ref"] == "a" * 64

    def test_a_ref_alone_is_a_record(self):
        value = parse_signup_attribution(
            {"captured_at": NOW.isoformat(), "landing_ref": "pricing_hero"}
        )
        assert value["landing_ref"] == "pricing_hero"

    @pytest.mark.django_db
    def test_the_function_reads_it_back(self):
        from stapel_core.comm import call

        user = User.objects.create(email=_email(), auth_type="email")
        record_signup_attribution(user, self._parse("transcribe_hero"))
        answer = call("auth.signup_attribution", {"user_id": str(user.pk)})
        assert answer["landing_ref"] == "transcribe_hero"

    @pytest.mark.django_db
    def test_an_invalid_ref_never_fails_the_sign_up(self, client):
        email = _email()
        response = _email_verify(client, email, UTM_ONLY | {"landing_ref": "Bad Ref"})
        assert response.status_code == 200, response.data
        row = SignupAttribution.objects.get(user__email=email)
        assert row.utm_source == "newsletter"
        assert row.landing_ref == ""
