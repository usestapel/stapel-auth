"""``stapel_auth.testing``: the helpers a consuming project's suite registers.

This module deliberately does NOT clear the cache between its tests: a
project's suite usually does not either, and the OTP limiter lives there.
"""

import pytest
from django.core.cache import cache

from stapel_auth.otp.serializers import normalize_phone
from stapel_auth import testing as helpers
from stapel_auth.testing import _self_check, unique_email, unique_phone

# A project registers the plugin with pytest_plugins; a test module of the
# library itself picks the fixtures up by binding them at module level.
signed_in_client = helpers.signed_in_client
otp_limiter_off = helpers.otp_limiter_off

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _isolate_cache():
    """Overrides the suite's per-test cache clear: the limiter must persist."""
    yield


@pytest.fixture(autouse=True, scope="module")
def _clean_module_cache():
    cache.clear()
    yield
    cache.clear()


def test_first_sign_in_under_the_default_limiter(signed_in_client):
    client = signed_in_client()
    me = client.get("/auth/api/v1/me/")
    assert me.status_code == 200, me.content
    assert client.user.phone == client.phone


def test_second_sign_in_back_to_back_under_the_default_limiter(signed_in_client):
    first, second = signed_in_client(), signed_in_client()
    assert first.user.pk != second.user.pk
    assert first.get("/auth/api/v1/me/").status_code == 200


def test_a_fixed_phone_trips_the_default_limiter(signed_in_client):
    """Guard: the limiter is live here, so the tests above prove something."""
    phone = unique_phone()
    signed_in_client(phone)
    with pytest.raises(AssertionError, match="phone_request .* answered 429"):
        signed_in_client(phone)


def test_otp_limiter_off_lets_one_phone_sign_in_repeatedly(otp_limiter_off, signed_in_client):
    phone = unique_phone()
    users = {signed_in_client(phone).user.pk for _ in range(5)}
    assert len(users) == 1


def test_unique_phone_is_valid_e164_and_unique():
    phones = [unique_phone() for _ in range(300)]
    assert len(set(phones)) == 300
    assert all(normalize_phone(p) == p for p in phones)


def test_self_check_refuses_an_invalid_number():
    with pytest.raises(ValueError, match="not a valid phone"):
        _self_check("+15550100")


def test_self_check_refuses_a_number_that_is_not_e164_already():
    with pytest.raises(ValueError, match="normalizes to"):
        _self_check("+1 202 555 0123")


def test_unique_email_is_unique_and_reserved():
    emails = {unique_email() for _ in range(50)}
    assert len(emails) == 50
    assert all(e.endswith("@example.com") for e in emails)


def test_helpers_are_listed_with_a_first_docstring_line():
    assert sorted(helpers.__all__) == [
        "otp_limiter_off", "signed_in_client", "unique_email", "unique_phone",
    ]
    for name in helpers.__all__:
        doc = (getattr(helpers, name).__doc__ or "").strip()
        assert doc.splitlines()[0], name


def test_no_pytest11_entry_point():
    from importlib.metadata import entry_points

    assert not [ep for ep in entry_points(group="pytest11") if ep.value.startswith("stapel_auth")]
