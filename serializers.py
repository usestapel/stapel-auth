from rest_framework import serializers
from drf_spectacular.utils import PolymorphicProxySerializer
from stapel_core.django.serializers import IronDataclassSerializer
from stapel_core.django.errors import IronValidationError
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from .models import ServiceAPIKey
from .errors import (
    ERR_400_INVALID_PHONE_FORMAT, ERR_400_INVALID_PHONE, ERR_400_PHONE_TOO_LONG,
    ERR_400_PASSWORDS_DONT_MATCH, ERR_400_EMAIL_OR_PHONE_REQUIRED,
    ERR_400_EMAIL_OR_PHONE_NOT_BOTH,
)
from .dto import (
    TokenPairResponse,
    AuthResponse,
    TokenVerifyResponse,
    OtpSentResponse,
    LogoutResponse,
    InstantRequestOldResponse,
    InstantVerifyOldResponse,
    InstantRequestNewResponse,
    DelayedInitiateResponse,
    DelayedStatusResponse,
    DelayedCancelResponse,
    PasswordMethod,
    PasswordMethodsResponse,
    PasswordMethodType,
    TOTPChallengeResponse,
    QRGenerateResponse,
    QRStatusResponse,
    QRType,
    SecurityStatusPassword,
    SecurityStatusTOTP,
    SecurityStatusContact,
    SecurityStatusOAuth,
    SecurityStatusSessions,
    SecurityStatusPasskeys,
    SecurityStatusResponse,
    TOTPSetupResponse,
    TOTPSetupConfirmResponse,
    TOTPStepUpResponse,
    SimpleStatusResponse,
    SessionResponse,
)
import phonenumbers


def normalize_phone(value):
    """Parse and normalize phone number to E.164 format (+79991234567)."""
    try:
        phone_number = phonenumbers.parse(value, None)
    except phonenumbers.NumberParseException:
        raise IronValidationError(ERR_400_INVALID_PHONE_FORMAT)
    if not phonenumbers.is_valid_number(phone_number):
        raise IronValidationError(ERR_400_INVALID_PHONE)
    e164 = phonenumbers.format_number(phone_number, phonenumbers.PhoneNumberFormat.E164)
    if len(e164) > 16:  # E.164: '+' + up to 15 digits
        raise IronValidationError(ERR_400_PHONE_TOO_LONG)
    return e164

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'phone', 'auth_type',
            'is_email_verified', 'is_phone_verified', 'is_anonymous',
            'is_staff', 'is_superuser',
            'oauth_provider', 'avatar', 'bio', 'created_at', 'last_login',
            'onboarding_completed', 'profile_completed'
        ]
        # ``is_staff`` / ``is_superuser`` are pinned read-only here so a
        # PATCH /me/ can never let a user privilege-escalate by sending
        # the field back. They're already in the JWT claims; surfacing
        # them on /me/ just saves the frontend from decoding the token.
        read_only_fields = [
            'id', 'auth_type', 'is_email_verified', 'is_phone_verified',
            'is_anonymous', 'is_staff', 'is_superuser',
            'oauth_provider', 'created_at', 'last_login'
        ]


class TokenPairSerializer(IronDataclassSerializer):
    """Serializer for JWT token pair."""
    class Meta:
        dataclass = TokenPairResponse


class AuthResponseSerializer(IronDataclassSerializer):
    """Serializer for authentication response with user and tokens."""
    user = UserSerializer(read_only=True)

    class Meta:
        dataclass = AuthResponse


class TokenVerifyResponseSerializer(IronDataclassSerializer):
    """Serializer for token verify response."""
    user = UserSerializer()

    class Meta:
        dataclass = TokenVerifyResponse


class EmailAuthRequestSerializer(serializers.Serializer):
    """Serializer for email authentication request (OTP)"""
    email = serializers.EmailField()
    device_id = serializers.CharField(max_length=255, required=False)


class EmailAuthVerifySerializer(serializers.Serializer):
    """Serializer for email verification (OTP)"""
    email = serializers.EmailField()
    code = serializers.CharField(max_length=4)


class PhoneAuthRequestSerializer(serializers.Serializer):
    """Serializer for phone authentication request"""
    phone = serializers.CharField()
    device_id = serializers.CharField(max_length=255, required=False)

    def validate_phone(self, value):
        return normalize_phone(value)


class PhoneAuthVerifySerializer(serializers.Serializer):
    """Serializer for phone verification"""
    phone = serializers.CharField()
    code = serializers.CharField(max_length=4)

    def validate_phone(self, value):
        return normalize_phone(value)


class AnonymousAuthSerializer(serializers.Serializer):
    """Serializer for anonymous authentication"""
    device_id = serializers.CharField(max_length=255, required=False)


class OAuthSerializer(serializers.Serializer):
    """Serializer for OAuth authentication"""
    provider = serializers.CharField(max_length=50)
    access_token = serializers.CharField(max_length=500)


class ServiceAPIKeySerializer(serializers.ModelSerializer):
    """Serializer for Service API Keys"""

    class Meta:
        model = ServiceAPIKey
        fields = ['id', 'name', 'key', 'description', 'is_active', 'created_at', 'last_used_at', 'allowed_endpoints']
        read_only_fields = ['id', 'key', 'created_at', 'last_used_at']


class EmailVerificationSerializer(serializers.Serializer):
    """Serializer for email verification"""
    uid = serializers.CharField()
    token = serializers.CharField()


class PasswordResetSerializer(serializers.Serializer):
    """Serializer for password reset request"""
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation"""
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password2']:
            raise IronValidationError(ERR_400_PASSWORDS_DONT_MATCH)
        return attrs


class TokenVerifySerializer(serializers.Serializer):
    """Serializer for token verification"""
    token = serializers.CharField()


class ConvertAnonymousUserSerializer(serializers.Serializer):
    """Serializer for converting anonymous user to registered user via OTP"""
    email = serializers.EmailField(required=False)
    phone = serializers.CharField(required=False)
    code = serializers.CharField(max_length=4, required=True)

    def validate_phone(self, value):
        if not value:
            return value
        return normalize_phone(value)

    def validate(self, attrs):
        if not attrs.get('email') and not attrs.get('phone'):
            raise IronValidationError(ERR_400_EMAIL_OR_PHONE_REQUIRED)

        if attrs.get('email') and attrs.get('phone'):
            raise IronValidationError(ERR_400_EMAIL_OR_PHONE_NOT_BOTH)

        return attrs


# ── Authenticator Change serializers ──────────────────────────


class InstantChangeRequestOldSerializer(serializers.Serializer):
    """Request OTP to current (old) authenticator."""
    device_id = serializers.CharField(max_length=255, required=False)


class InstantChangeVerifyOldSerializer(serializers.Serializer):
    """Verify OTP from old authenticator."""
    code = serializers.CharField(max_length=4)


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
        if not attrs.get('phone') and not attrs.get('email'):
            raise IronValidationError(ERR_400_EMAIL_OR_PHONE_REQUIRED)
        return attrs


class InstantChangeVerifyNewSerializer(serializers.Serializer):
    """Verify OTP from new authenticator and apply change."""
    phone = serializers.CharField(required=False)
    email = serializers.EmailField(required=False)
    code = serializers.CharField(max_length=4)
    change_token = serializers.UUIDField()

    def validate_phone(self, value):
        if not value:
            return value
        return normalize_phone(value)

    def validate(self, attrs):
        if not attrs.get('phone') and not attrs.get('email'):
            raise IronValidationError(ERR_400_EMAIL_OR_PHONE_REQUIRED)
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
        if not attrs.get('phone') and not attrs.get('email'):
            raise IronValidationError(ERR_400_EMAIL_OR_PHONE_REQUIRED)
        return attrs


class DelayedChangeCancelSerializer(serializers.Serializer):
    """Cancel a pending delayed change request."""
    change_request_id = serializers.UUIDField()


# =============================================================================
# Dataclass Serializers
# =============================================================================


class OtpSentResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = OtpSentResponse


class LogoutResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = LogoutResponse


class InstantRequestOldResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = InstantRequestOldResponse


class InstantVerifyOldResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = InstantVerifyOldResponse


class InstantRequestNewResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = InstantRequestNewResponse


class DelayedInitiateResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = DelayedInitiateResponse


class DelayedStatusResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = DelayedStatusResponse


class DelayedCancelResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = DelayedCancelResponse


# ── Password serializers ──────────────────────────────────────────────────────

class PasswordLoginSerializer(serializers.Serializer):
    login = serializers.CharField(help_text='Email or username')
    password = serializers.CharField()


class PasswordChangeDirectSerializer(serializers.Serializer):
    old_password = serializers.CharField()
    new_password = serializers.CharField(min_length=8)

    def validate_new_password(self, value):
        from django.contrib.auth.password_validation import validate_password
        validate_password(value)
        return value


class PasswordOtpRequestSerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=[PasswordMethodType.EMAIL, PasswordMethodType.PHONE])


class PasswordOtpVerifySerializer(serializers.Serializer):
    method = serializers.ChoiceField(choices=[PasswordMethodType.EMAIL, PasswordMethodType.PHONE])
    code = serializers.CharField(max_length=4)
    new_password = serializers.CharField(min_length=8)

    def validate_new_password(self, value):
        from django.contrib.auth.password_validation import validate_password
        validate_password(value)
        return value


class PasswordResetEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetEmailVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=4)
    new_password = serializers.CharField(min_length=8)

    def validate_new_password(self, value):
        validate_password(value)
        return value


class PasswordResetPhoneRequestSerializer(serializers.Serializer):
    phone = serializers.CharField()

    def validate_phone(self, value):
        return normalize_phone(value)


class PasswordResetPhoneVerifySerializer(serializers.Serializer):
    phone = serializers.CharField()
    code = serializers.CharField(max_length=4)
    new_password = serializers.CharField(min_length=8)

    def validate_phone(self, value):
        return normalize_phone(value)

    def validate_new_password(self, value):
        validate_password(value)
        return value


class PasswordMethodSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = PasswordMethod


class PasswordMethodsResponseSerializer(IronDataclassSerializer):
    methods = PasswordMethodSerializer(many=True)

    class Meta:
        dataclass = PasswordMethodsResponse


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


class TOTPChallengeResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = TOTPChallengeResponse


# Polymorphic union: password login / oauth login return either a full
# AuthResponse (status=LOGGED_IN/REGISTERED) or a TOTPChallengeResponse
# (status=TOTP_REQUIRED). The `status` field is the discriminator.
# drf-spectacular emits oneOf + discriminator so API generators produce
# a proper TypeScript union with type narrowing.
LoginResponseSerializer = PolymorphicProxySerializer(
    component_name='LoginResponse',
    serializers=[AuthResponseSerializer, TOTPChallengeResponseSerializer],
    resource_type_field_name='status',
)


# ── QR auth serializers ────────────────────────────────────────────────────────

class QRGenerateSerializer(serializers.Serializer):
    type = serializers.ChoiceField(
        choices=[e.value for e in QRType],
        help_text=(
            '`session_share` — logged-in user generates a QR to share their session with a scanner (e.g. log into a new device). Requires auth. '
            '`login_request` — unauthenticated device generates a QR and waits for a logged-in scanner to approve the login.'
        ),
    )
    redirect_url = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        default=None,
        help_text=(
            'Where to redirect the scanner after successful auth. '
            'Must be a relative path starting with / (e.g. /home). '
            'For `session_share`: the scanning device lands here after receiving the session. '
            'For `login_request`: the confirming device lands here after approving. '
            'Defaults to `/` if omitted.'
        ),
    )

    def validate_redirect_url(self, value):
        if not value:
            return value
        if value.startswith('/'):
            return value
        raise serializers.ValidationError(
            'redirect_url must be a relative path starting with /  — absolute URLs are not allowed.'
        )


class QRGenerateResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = QRGenerateResponse


class QRStatusResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = QRStatusResponse

# =============================================================================
# Security Status serializers
# =============================================================================

class SecurityStatusPasswordSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusPassword


class SecurityStatusTOTPSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusTOTP


class SecurityStatusContactSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusContact


class SecurityStatusOAuthSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusOAuth


class SecurityStatusSessionsSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusSessions


class SecurityStatusPasskeysSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusPasskeys


class SecurityStatusResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = SecurityStatusResponse


# =============================================================================
# TOTP setup serializers
# =============================================================================

class TOTPSetupResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = TOTPSetupResponse


class TOTPSetupConfirmResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = TOTPSetupConfirmResponse


class TOTPStepUpResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = TOTPStepUpResponse


class SimpleStatusSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = SimpleStatusResponse


class SessionResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = SessionResponse
