"""Serializers for the step-up verification endpoints."""
from rest_framework import serializers
from stapel_core.django.api.serializers import StapelDataclassSerializer

from stapel_auth.verification.dto import (
    VerificationChallengeInfoResponse,
    VerificationCompleteResponse,
    VerificationInitiateResponse,
)


class VerificationInitiateSerializer(serializers.Serializer):
    """Request body for initiating a verification factor."""

    factor = serializers.CharField(
        help_text="Factor id from the challenge's factor list, e.g. otp_email."
    )


class VerificationCompleteSerializer(serializers.Serializer):
    """Request body for completing a verification challenge.

    ``factor`` selects the factor; the remaining fields are the factor's
    proof payload — ``code`` / ``backup_code`` for OTP/TOTP factors,
    ``session_key`` + ``credential`` for the passkey assertion.
    """

    factor = serializers.CharField(
        help_text="Factor id from the challenge's factor list, e.g. otp_email."
    )
    code = serializers.CharField(
        required=False, allow_blank=True,
        help_text="One-time / TOTP code (otp_email, otp_phone, totp).",
    )
    backup_code = serializers.CharField(
        required=False, allow_blank=True,
        help_text="TOTP backup code (totp factor only).",
    )
    session_key = serializers.CharField(
        required=False, allow_blank=True,
        help_text="WebAuthn ceremony key returned by initiate (passkey).",
    )
    credential = serializers.JSONField(
        required=False,
        help_text="WebAuthn assertion from navigator.credentials.get (passkey).",
    )


class VerificationChallengeInfoResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = VerificationChallengeInfoResponse


class VerificationInitiateResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = VerificationInitiateResponse


class VerificationCompleteResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = VerificationCompleteResponse
