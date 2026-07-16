"""
Serializers for OTP authentication flows and authenticator change flows.
"""

import phonenumbers
from rest_framework import serializers
from stapel_core.django.api.errors import StapelValidationError
from stapel_core.django.api.serializers import StapelDataclassSerializer
from stapel_core.django.captcha import CaptchaMixin

from stapel_auth.errors import (
    ERR_400_EMAIL_OR_PHONE_NOT_BOTH,
    ERR_400_EMAIL_OR_PHONE_REQUIRED,
    ERR_400_INVALID_PHONE,
    ERR_400_INVALID_PHONE_FORMAT,
    ERR_400_PHONE_TOO_LONG,
)
from stapel_auth.otp.constants import OTP_CODE_LENGTH
from stapel_auth.otp.dto import (
    DelayedCancelResponse,
    DelayedInitiateResponse,
    DelayedStatusResponse,
    InstantRequestNewResponse,
    InstantRequestOldResponse,
    InstantVerifyOldResponse,
    OtpSentResponse,
)


def normalize_phone(value):
    """Parse and normalize phone number to E.164 format (+79991234567)."""
    try:
        phone_number = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException:
        raise StapelValidationError(ERR_400_INVALID_PHONE_FORMAT)
    if not phonenumbers.is_valid_number(phone_number):
        raise StapelValidationError(ERR_400_INVALID_PHONE)
    e164 = phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.E164)
    if len(e164) > 16:  # E.164: '+' + up to 15 digits
        raise StapelValidationError(ERR_400_PHONE_TOO_LONG)
    return e164


class EmailAuthRequestSerializer(CaptchaMixin, serializers.Serializer):
    """Serializer for email authentication request (OTP)"""

    email = serializers.EmailField()
    device_id = serializers.CharField(max_length=255, required=False)
    captcha_token = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        self._require_captcha_if_configured(attrs)
        return attrs


class EmailAuthVerifySerializer(serializers.Serializer):
    """Serializer for email verification (OTP)"""

    email = serializers.EmailField()
    code = serializers.CharField(max_length=OTP_CODE_LENGTH)


class PhoneAuthRequestSerializer(CaptchaMixin, serializers.Serializer):
    """Serializer for phone authentication request"""

    phone = serializers.CharField()
    device_id = serializers.CharField(max_length=255, required=False)
    captcha_token = serializers.CharField(required=False, allow_blank=True)

    def validate_phone(self, value):
        return normalize_phone(value)

    def validate(self, attrs):
        self._require_captcha_if_configured(attrs)
        return attrs


class PhoneAuthVerifySerializer(serializers.Serializer):
    """Serializer for phone verification"""

    phone = serializers.CharField()
    code = serializers.CharField(max_length=OTP_CODE_LENGTH)

    def validate_phone(self, value):
        return normalize_phone(value)


class AnonymousAuthSerializer(serializers.Serializer):
    """Serializer for anonymous authentication"""

    device_id = serializers.CharField(max_length=255, required=False)


class OtpSentResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = OtpSentResponse


class EmailVerificationSerializer(serializers.Serializer):
    """Serializer for email verification"""

    uid = serializers.CharField()
    token = serializers.CharField()


class ConvertAnonymousUserSerializer(serializers.Serializer):
    """Serializer for converting anonymous user to registered user via OTP"""

    email = serializers.EmailField(required=False)
    phone = serializers.CharField(required=False)
    code = serializers.CharField(max_length=OTP_CODE_LENGTH, required=True)

    def validate_phone(self, value):
        if not value:
            return value
        return normalize_phone(value)

    def validate(self, attrs):
        if not attrs.get("email") and not attrs.get("phone"):
            raise StapelValidationError(ERR_400_EMAIL_OR_PHONE_REQUIRED)

        if attrs.get("email") and attrs.get("phone"):
            raise StapelValidationError(ERR_400_EMAIL_OR_PHONE_NOT_BOTH)

        return attrs


# ── Authenticator Change serializers ──────────────────────────


class InstantChangeRequestOldSerializer(serializers.Serializer):
    """Request OTP to current (old) authenticator."""

    device_id = serializers.CharField(max_length=255, required=False)


class InstantChangeVerifyOldSerializer(serializers.Serializer):
    """Verify OTP from old authenticator."""

    code = serializers.CharField(max_length=OTP_CODE_LENGTH)


class InstantChangeRequestNewSerializer(serializers.Serializer):
    """Request OTP to new authenticator (phone or email)."""

    phone = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    change_token = serializers.UUIDField()

    def validate_phone(self, value):
        if not value:
            return value
        return normalize_phone(value)

    def validate(self, attrs):
        if not attrs.get("phone") and not attrs.get("email"):
            raise StapelValidationError(ERR_400_EMAIL_OR_PHONE_REQUIRED)
        return attrs


class InstantChangeVerifyNewSerializer(serializers.Serializer):
    """Verify OTP from new authenticator and apply change."""

    phone = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    code = serializers.CharField(max_length=OTP_CODE_LENGTH)
    change_token = serializers.UUIDField()

    def validate_phone(self, value):
        if not value:
            return value
        return normalize_phone(value)

    def validate(self, attrs):
        if not attrs.get("phone") and not attrs.get("email"):
            raise StapelValidationError(ERR_400_EMAIL_OR_PHONE_REQUIRED)
        return attrs


class DelayedChangeInitiateSerializer(serializers.Serializer):
    """Initiate a delayed (14-day) authenticator change."""

    phone = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    device_id = serializers.CharField(max_length=255, required=False)

    def validate_phone(self, value):
        if not value:
            return value
        return normalize_phone(value)

    def validate(self, attrs):
        if not attrs.get("phone") and not attrs.get("email"):
            raise StapelValidationError(ERR_400_EMAIL_OR_PHONE_REQUIRED)
        return attrs


class DelayedChangeCancelSerializer(serializers.Serializer):
    """Cancel a pending delayed change request."""

    change_request_id = serializers.UUIDField()


class InstantRequestOldResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = InstantRequestOldResponse


class InstantVerifyOldResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = InstantVerifyOldResponse


class InstantRequestNewResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = InstantRequestNewResponse


class DelayedInitiateResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = DelayedInitiateResponse


class DelayedStatusResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = DelayedStatusResponse


class DelayedCancelResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = DelayedCancelResponse
