"""`OtpSentResponse.target` never carries the address it stands for.

The field exists so a client can render "code sent to u***@example.com" on a
screen the sender may be reading over a shoulder, and the contract has always
described it as masked — ``OtpSentResponse.target``'s own docstring, the
generated ``auth.d.ts``, and every consumer doc say ``u***@example.com``.

The two OTP request views handed back the raw address anyway (measured against
production on 2026-09-14: ``POST /email/request/`` answered with the full
e-mail), while the password and MFA views on the same DTO masked theirs. A
promise kept by four call sites out of six is not a promise, so the masking
moved into the serializer: whatever a producer puts in the dataclass, what
leaves over HTTP is masked. The call sites still mask too — the mask is
idempotent — so the DTO is never the thing carrying an address around.
"""
import uuid

import pytest
from django.urls import reverse
from rest_framework.test import APIClient

pytestmark = pytest.mark.django_db


def _client():
    return APIClient()


class TestEmailRequestMasksTheTarget:
    def test_response_target_is_masked(self):
        email = f"masking_{uuid.uuid4().hex[:8]}@example.com"
        resp = _client().post(reverse("email_request"), {"email": email})
        assert resp.status_code == 200, resp.content
        target = resp.data["target"]
        assert target != email
        assert email not in target
        local, domain = email.split("@")
        assert target == f"{local[0]}***@{domain}"

    def test_the_local_part_does_not_leak_through_the_mask(self):
        email = f"alexandra.{uuid.uuid4().hex[:6]}@example.com"
        resp = _client().post(reverse("email_request"), {"email": email})
        assert resp.status_code == 200, resp.content
        assert "alexandra" not in resp.data["target"]


class TestPhoneRequestMasksTheTarget:
    def test_response_target_is_masked(self):
        phone = "+12025550123"
        resp = _client().post(reverse("phone_request"), {"phone": phone})
        assert resp.status_code == 200, resp.content
        target = resp.data["target"]
        assert target != phone
        assert phone not in target
        # Enough digits to recognise the number you own, not enough to be one.
        assert target.endswith("01 23")
        assert "5550" not in target.replace(" ", "")


class TestMaskTarget:
    """The serializer's choke point, exercised directly."""

    def test_email_keeps_the_first_character_and_the_domain(self):
        from stapel_auth.utils import mask_target

        assert mask_target("user@example.com") == "u***@example.com"

    def test_phone_keeps_the_last_four_digits(self):
        from stapel_auth.utils import mask_target

        assert mask_target("+79994561234") == "+7 *** *** 12 34"

    def test_an_already_masked_value_survives_unchanged(self):
        """Idempotence is what lets the call sites keep masking too.

        ``PasswordService.mask_phone`` renders ``+79***34``; running the phone
        mask over that again would eat the country code and hand the user a
        different-looking number than the one they typed.
        """
        from stapel_auth.utils import mask_target

        for already in ("u***@example.com", "+7 *** *** 12 34", "+79***34", "***"):
            assert mask_target(already) == already

    def test_empty_stays_empty(self):
        from stapel_auth.utils import mask_target

        assert mask_target("") == ""
        assert mask_target(None) is None


class TestSerializerIsTheChokePoint:
    """A producer that forgets to mask cannot leak through this serializer."""

    def test_raw_email_in_the_dataclass_is_masked_on_the_way_out(self):
        from stapel_auth.otp.dto import OtpSentResponse
        from stapel_auth.otp.serializers import OtpSentResponseSerializer

        dto = OtpSentResponse(message="sent", target="user@example.com")
        assert OtpSentResponseSerializer(dto).data["target"] == "u***@example.com"

    def test_raw_phone_in_the_dataclass_is_masked_on_the_way_out(self):
        from stapel_auth.otp.dto import OtpSentResponse
        from stapel_auth.otp.serializers import OtpSentResponseSerializer

        dto = OtpSentResponse(message="sent", target="+79994561234")
        assert OtpSentResponseSerializer(dto).data["target"] == "+7 *** *** 12 34"
