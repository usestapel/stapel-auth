"""Serializers for MFA (TOTP and Passkey) domain."""
from rest_framework import serializers
from drf_spectacular.utils import PolymorphicProxySerializer
from stapel_core.django.api.serializers import StapelDataclassSerializer

from stapel_auth.mfa.dto import (
    TOTPChallengeResponse,
    TOTPSetupResponse,
    TOTPSetupConfirmResponse,
)
from stapel_auth.mfa.services import TOTPService
from stapel_auth.otp.constants import OTP_CODE_LENGTH

_TOTP_LEN = TOTPService.CODE_LENGTH


# ── TOTP serializers ─────────────────────────────────────────────────────────

class TOTPChallengeVerifySerializer(serializers.Serializer):
    challenge_token = serializers.CharField(help_text='Opaque token from TOTPChallengeResponse.')
    code = serializers.CharField(max_length=_TOTP_LEN, required=False,
                                 help_text=f'{_TOTP_LEN}-digit TOTP code from authenticator app.')
    backup_code = serializers.CharField(required=False,
                                        help_text='One-time backup code.')


class TOTPSetupRequestSerializer(serializers.Serializer):
    """Optional proof for a *replace* (an active device already exists).

    Both fields are optional because first-time enrollment (no active
    device) needs neither — TOTPService.setup() only enforces one of them
    when there is something to prove possession of.
    """
    code = serializers.CharField(max_length=_TOTP_LEN, required=False, allow_blank=True,
                                 help_text=f'{_TOTP_LEN}-digit code from the CURRENT authenticator app (required to replace an active device).')
    backup_code = serializers.CharField(required=False, allow_blank=True,
                                        help_text='A current backup code (alternative to code, to replace an active device).')


class TOTPSetupConfirmSerializer(serializers.Serializer):
    code = serializers.CharField(max_length=_TOTP_LEN, help_text=f'{_TOTP_LEN}-digit code from authenticator app.')


class TOTPDelayedInitiateSerializer(serializers.Serializer):
    """Initiate a delayed (14-day) TOTP removal — no old-device proof available."""
    device_id = serializers.CharField(max_length=255, required=False)


class TOTPDisableOtpRequestSerializer(serializers.Serializer):
    pass  # no input — OTP sent to verified phone


class _TOTPDisableByTOTPSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=['totp'])
    code = serializers.CharField(max_length=_TOTP_LEN, help_text=f'{_TOTP_LEN}-digit TOTP code from authenticator app.')


class _TOTPDisableByBackupSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=['backup'])
    backup_code = serializers.CharField(help_text='One-time backup code.')


class _TOTPDisableByOTPSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=['otp'])
    otp_code = serializers.CharField(max_length=OTP_CODE_LENGTH,
                                     help_text=f'{OTP_CODE_LENGTH}-digit code sent to phone via /totp/disable-otp/request/.')


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


# ── Passkey serializers ───────────────────────────────────────────────────────

class PasskeyItemSerializer(serializers.Serializer):
    id           = serializers.CharField()
    device_name  = serializers.CharField()
    aaguid       = serializers.CharField()
    transports   = serializers.ListField(child=serializers.CharField())
    created_at   = serializers.DateTimeField()
    last_used_at = serializers.DateTimeField(allow_null=True)
