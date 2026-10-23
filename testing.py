"""Test helpers for projects that install stapel-auth (a pytest plugin).

Register it explicitly in the project's root ``conftest.py``::

    pytest_plugins = ["stapel_auth.testing"]

Nothing loads it uninvited: there is no ``pytest11`` entry point. The fixtures
need pytest-django (``settings``, ``db``). The module imports nothing from
Django at import time, so it is safe to list before ``django.setup()``.

The default OTP limiter (``OTP_RATE_LIMIT_PER_HOUR`` sends per identifier and
an ``OTP_RESEND_COOLDOWN`` between sends) lives in the cache, which a project's
suite does not usually clear between tests. A test that signs in with a fixed
phone therefore fails from its fourth run in an hour; ``unique_phone()`` gives
every sign-in its own identifier, so the limiter stays on and out of the way.
"""

from __future__ import annotations

import itertools
import random
import secrets

import pytest

__all__ = ["otp_limiter_off", "signed_in_client", "unique_email", "unique_phone"]

# NANP 555-0100..0199 is reserved for fiction in every area code: these
# numbers are valid for libphonenumber and never reach a real subscriber.
_AREA_CODES = (
    201, 202, 203, 205, 206, 207, 208, 212, 213, 214, 215, 216, 217, 218, 301,
    303, 304, 305, 312, 313, 314, 401, 402, 404, 405, 406, 407, 408, 410, 412,
    415, 503, 504, 505, 512, 602, 617, 702, 713, 801, 802, 808, 812, 816, 901,
    904, 914, 916, 919, 971,
)
_POOL = len(_AREA_CODES) * 100
_phone_seq = itertools.count(random.SystemRandom().randrange(_POOL))
_email_seq = itertools.count(1)
_RUN = secrets.token_hex(3)


def _self_check(phone: str) -> str:
    """``phone`` in E.164 as stapel-auth's own validator normalizes it.

    Raises ``ValueError`` for a number the sign-in endpoints would refuse.
    """
    from stapel_auth.otp.serializers import normalize_phone

    try:
        normalized = normalize_phone(phone)
    except Exception as exc:  # StapelValidationError carries the error key
        raise ValueError(f"{phone!r} is not a valid phone for stapel-auth: {exc}") from exc
    if normalized != phone:
        raise ValueError(f"{phone!r} normalizes to {normalized!r}, not to itself")
    return normalized


def unique_phone() -> str:
    """A fresh valid E.164 phone (a fictional NANP 555-01XX number) per call."""
    n = next(_phone_seq) % _POOL
    area, line = _AREA_CODES[n // 100], 100 + n % 100
    return _self_check(f"+1{area}555{line:04d}")


def unique_email() -> str:
    """A fresh e-mail address per call, on the reserved ``example.com`` domain."""
    return f"user-{_RUN}-{next(_email_seq)}@example.com"


def _mock_sms(settings) -> str:
    """Turn the SMS channel's mock on for this test; return the code it issues."""
    from stapel_auth.conf import auth_settings

    settings.STAPEL_AUTH = {
        **(getattr(settings, "STAPEL_AUTH", None) or {}),
        "USE_MOCK_SMS_OTP": True,
    }
    auth_settings.reload()
    return str(auth_settings.MOCK_OTP_CODE)


@pytest.fixture
def signed_in_client(db, settings):
    """Factory: ``signed_in_client(phone=None)`` returns an APIClient signed in by phone OTP.

    Each call runs the real flow (``phone_request`` then ``phone_verify``) with
    the SMS channel mocked for this test, so the client carries the session
    cookies the endpoints set, exactly as a browser would. ``phone`` defaults
    to ``unique_phone()``. The returned client has ``.user`` and ``.phone``.
    """
    from django.contrib.auth import get_user_model
    from django.urls import reverse
    from rest_framework.test import APIClient

    def sign_in(phone: str | None = None):
        code = _mock_sms(settings)
        phone = _self_check(phone) if phone else unique_phone()
        client = APIClient()
        # The proof a cookie-authenticated unsafe request carries when the host
        # turns on STAPEL_JWT_COOKIE_CSRF; harmless when it is off.
        client.credentials(HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        sent = client.post(reverse("phone_request"), {"phone": phone}, format="json")
        if sent.status_code != 200:
            raise AssertionError(
                f"phone_request for {phone} answered {sent.status_code}: {sent.content[:300]!r}"
            )
        verified = client.post(
            reverse("phone_verify"), {"phone": phone, "code": code}, format="json"
        )
        if verified.status_code != 200:
            raise AssertionError(
                f"phone_verify for {phone} answered {verified.status_code}: "
                f"{verified.content[:300]!r}"
            )
        client.user = get_user_model().objects.get(phone=phone)
        client.phone = phone
        return client

    return sign_in


@pytest.fixture
def otp_limiter_off(settings):
    """Opt-in: no hourly OTP cap and no resend cooldown for this test (never autouse)."""
    from django.core.cache import cache

    from stapel_auth.conf import auth_settings

    settings.STAPEL_AUTH = {
        **(getattr(settings, "STAPEL_AUTH", None) or {}),
        "OTP_RATE_LIMIT_PER_HOUR": 0,
        "OTP_RESEND_COOLDOWN": 0,
    }
    auth_settings.reload()
    cache.clear()
    yield
    cache.clear()
