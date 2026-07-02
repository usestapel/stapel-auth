"""Serializers for MFA (TOTP and Passkey) domain."""
from rest_framework import serializers
from drf_spectacular.utils import PolymorphicProxySerializer
from stapel_core.django.api.serializers import StapelDataclassSerializer

from stapel_auth.mfa.dto import (
    TOTPChallengeResponse,
    TOTPSetupResponse,
    TOTPSetupConfirmResponse,
    TOTPStepUpResponse,
)


# ── TOTP serializers ─────────────────────────────────────────────────────────

class TOTPChallengeVerifySerializer(serializers.Serializer):
    challenge_token = serializers.CharField(help_text='Opaque token from TOTPChallengeResponse.')
    code = serializers.CharField(max_length=6, required=False,
                                 help_text='6-digit TOTP code from authenticator app.')
    backup_code = serializers.CharField(required=False,
                                        help_text='One-time backup code.')


class TOTPSetupConfirmSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6, help_text='6-digit code from authenticator app.')


class TOTPStepUpSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=6, help_text='6-digit TOTP code.')


class TOTPDisableOtpRequestSerializer(serializers.Serializer):
    pass  # no input — OTP sent to verified phone


class _TOTPDisableByTOTPSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=['totp'])
    code = serializers.CharField(max_length=6, help_text='6-digit TOTP code from authenticator app.')


class _TOTPDisableByBackupSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=['backup'])
    backup_code = serializers.CharField(help_text='One-time backup code.')


class _TOTPDisableByOTPSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=['otp'])
    otp_code = serializers.CharField(max_length=4,
                                     help_text='4-digit code sent to phone via /totp/disable-otp/request/.')


TOTPDisableSerializer = PolymorphicProxySerializer(
    component_name='TOTPDisableRequest',
    serializers=[_TOTPDisableByTOTPSerializer, _TOTPDisableByBackupSerializer, _TOTPDisableByOTPSerializer],
    resource_type_field_name='method',
)


class TOTPChallengeResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = TOTPChallengeResponse


class TOTPSetupResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = TOTPSetupResponse


class TOTPSetupConfirmResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = TOTPSetupConfirmResponse


class TOTPStepUpResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = TOTPStepUpResponse


# ── Passkey serializers ───────────────────────────────────────────────────────

class PasskeyItemSerializer(serializers.Serializer):
    id           = serializers.CharField()
    device_name  = serializers.CharField()
    aaguid       = serializers.CharField()
    transports   = serializers.ListField(child=serializers.CharField())
    created_at   = serializers.DateTimeField()
    last_used_at = serializers.DateTimeField(allow_null=True)
