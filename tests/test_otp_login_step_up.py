"""Email/SMS code login owes the TOTP second factor, like password login.

A one-time code proves control of an inbox or a SIM — exactly what a TOTP
device is enrolled to protect against. Before this, ``/email/verify/`` and
``/phone/verify/`` issued a full session to an account with TOTP enrolled,
staff included, while ``/password/login/`` demanded the second factor.
"""
import uuid
from unittest.mock import patch

import pyotp
import pytest
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse
from rest_framework.test import APIClient

from stapel_auth.models import TOTPDevice

pytestmark = pytest.mark.django_db

User = get_user_model()
SECRET = "JBSWY3DPEHPK3PXP"


@pytest.fixture(autouse=True)
def _fresh_settings():
    cache.clear()
    from stapel_auth.conf import auth_settings

    auth_settings.reload()
    yield
    auth_settings.reload()


def _email_login(client, email):
    # Staff always get a real code (never the mock one), so the code is pinned.
    with patch(
        "stapel_auth.otp.services._OtpCodeService.generate_code", return_value="246810"
    ):
        assert client.post(reverse("email_request"), {"email": email}).status_code == 200
    return client.post(reverse("email_verify"), {"email": email, "code": "246810"})


def _totp_user(**extra):
    user = User.objects.create(
        email=f"totp_{uuid.uuid4().hex[:8]}@example.com", is_email_verified=True, **extra
    )
    TOTPDevice.objects.create(user=user, secret=SECRET, is_active=True)
    return user


@pytest.mark.parametrize("staff", [False, True])
def test_email_code_login_to_a_totp_account_returns_a_challenge(staff):
    user = _totp_user(is_staff=staff)
    client = APIClient()
    resp = _email_login(client, user.email)
    assert resp.status_code == 200, resp.content
    assert resp.data["status"] == "TOTP_REQUIRED"
    assert resp.data["challenge_token"]
    assert "tokens" not in resp.data
    assert "stapel_jwt" not in resp.cookies

    # The challenge is the ordinary one: the TOTP code finishes the login.
    done = client.post(
        reverse("totp_challenge_verify"),
        {"challenge_token": resp.data["challenge_token"], "code": pyotp.TOTP(SECRET).now()},
        format="json",
    )
    assert done.status_code == 200, done.content
    assert done.data["status"] == "LOGGED_IN"
    assert done.data["tokens"]["access"]


def test_phone_code_login_to_a_totp_account_returns_a_challenge():
    user = User.objects.create(phone="+12025550142", is_phone_verified=True)
    TOTPDevice.objects.create(user=user, secret=SECRET, is_active=True)
    client = APIClient()
    assert client.post(reverse("phone_request"), {"phone": user.phone}).status_code == 200
    resp = client.post(reverse("phone_verify"), {"phone": user.phone, "code": "0000"})
    assert resp.status_code == 200, resp.content
    assert resp.data["status"] == "TOTP_REQUIRED"
    assert "tokens" not in resp.data


def test_a_guest_merging_into_a_totp_account_gets_the_challenge_too():
    user = _totp_user()
    guest = User.create_anonymous_user()
    client = APIClient()
    client.force_authenticate(user=guest)
    resp = _email_login(client, user.email)
    assert resp.status_code == 200, resp.content
    assert resp.data["status"] == "TOTP_REQUIRED"


def test_an_account_without_totp_still_logs_straight_in():
    user = User.objects.create(
        email=f"plain_{uuid.uuid4().hex[:8]}@example.com", is_email_verified=True
    )
    resp = _email_login(APIClient(), user.email)
    assert resp.status_code == 200, resp.content
    assert resp.data["status"] == "LOGGED_IN"
    assert resp.data["tokens"]["access"]


def test_the_step_up_can_be_switched_off_explicitly():
    user = _totp_user()
    with override_settings(STAPEL_AUTH={"OTP_LOGIN_STEP_UP": False}):
        from stapel_auth.conf import auth_settings

        auth_settings.reload()
        resp = _email_login(APIClient(), user.email)
    assert resp.status_code == 200, resp.content
    assert resp.data["status"] == "LOGGED_IN"
