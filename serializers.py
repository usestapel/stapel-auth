"""Backward-compatibility shim — imports from sub-packages."""
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from drf_spectacular.utils import PolymorphicProxySerializer
from stapel_core.django.api.serializers import IronDataclassSerializer

from .dto import SimpleStatusResponse

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model."""

    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'phone', 'auth_type',
            'is_email_verified', 'is_phone_verified', 'is_anonymous',
            'is_staff', 'is_superuser',
            'oauth_provider', 'avatar', 'bio', 'created_at', 'last_login',
            'onboarding_completed', 'profile_completed',
        ]
        read_only_fields = [
            'id', 'auth_type', 'is_email_verified', 'is_phone_verified',
            'is_anonymous', 'is_staff', 'is_superuser',
            'oauth_provider', 'created_at', 'last_login',
        ]


class SimpleStatusSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = SimpleStatusResponse


# TOTPChallengeResponseSerializer must be importable from here because
# sessions/serializers.py imports it from stapel_auth.serializers at module level.
from stapel_auth.mfa.serializers import TOTPChallengeResponseSerializer  # noqa: E402

# ── Sessions serializers ──────────────────────────────────────────────────────
from stapel_auth.sessions.serializers import (  # noqa: E402
    TokenPairSerializer,
    AuthResponseSerializer,
    TokenVerifyResponseSerializer,
    TokenVerifySerializer,
    LogoutResponseSerializer,
    SessionResponseSerializer,
    LoginResponseSerializer,
)

# ── OTP serializers ───────────────────────────────────────────────────────────
from stapel_auth.otp.serializers import (  # noqa: E402
    EmailAuthRequestSerializer,
    EmailAuthVerifySerializer,
    PhoneAuthRequestSerializer,
    PhoneAuthVerifySerializer,
    AnonymousAuthSerializer,
    OtpSentResponseSerializer,
    EmailVerificationSerializer,
    ConvertAnonymousUserSerializer,
    InstantChangeRequestOldSerializer,
    InstantChangeVerifyOldSerializer,
    InstantChangeRequestNewSerializer,
    InstantChangeVerifyNewSerializer,
    DelayedChangeInitiateSerializer,
    DelayedChangeCancelSerializer,
    InstantRequestOldResponseSerializer,
    InstantVerifyOldResponseSerializer,
    InstantRequestNewResponseSerializer,
    DelayedInitiateResponseSerializer,
    DelayedStatusResponseSerializer,
    DelayedCancelResponseSerializer,
)

# ── OAuth serializers ─────────────────────────────────────────────────────────
from stapel_auth.oauth.serializers import (  # noqa: E402
    OAuthSerializer,
    OAuthProviderInfoSerializer,
    RegistrationCapabilitiesSerializer,
    LoginCapabilitiesSerializer,
    AuthCapabilitiesSerializer,
)

# ── Password serializers ──────────────────────────────────────────────────────
from stapel_auth.password.serializers import (  # noqa: E402
    PasswordLoginSerializer,
    PasswordChangeDirectSerializer,
    PasswordOtpRequestSerializer,
    PasswordOtpVerifySerializer,
    PasswordResetEmailRequestSerializer,
    PasswordResetEmailVerifySerializer,
    PasswordResetPhoneRequestSerializer,
    PasswordResetPhoneVerifySerializer,
    PasswordResetSerializer,
    PasswordResetConfirmSerializer,
    PasswordMethodSerializer,
    PasswordMethodsResponseSerializer,
    PasswordRegisterSerializer,
)

# ── MFA (TOTP + Passkey) serializers ─────────────────────────────────────────
from stapel_auth.mfa.serializers import (  # noqa: E402
    TOTPChallengeVerifySerializer,
    TOTPSetupConfirmSerializer,
    TOTPStepUpSerializer,
    TOTPDisableOtpRequestSerializer,
    TOTPDisableSerializer,
    TOTPSetupResponseSerializer,
    TOTPSetupConfirmResponseSerializer,
    TOTPStepUpResponseSerializer,
)

# ── QR serializers ────────────────────────────────────────────────────────────
from stapel_auth.qr.serializers import (  # noqa: E402
    QRGenerateSerializer,
    QRGenerateResponseSerializer,
    QRStatusResponseSerializer,
)

# ── Security serializers ──────────────────────────────────────────────────────
from stapel_auth.security.serializers import (  # noqa: E402
    SecurityStatusPasswordSerializer,
    SecurityStatusTOTPSerializer,
    SecurityStatusContactSerializer,
    SecurityStatusOAuthSerializer,
    SecurityStatusSessionsSerializer,
    SecurityStatusPasskeysSerializer,
    SecurityStatusResponseSerializer,
    AuditLogEntrySerializer,
    AuditLogPageSerializer,
)

# ── Admin serializers ─────────────────────────────────────────────────────────
from stapel_auth.admin.serializers import (  # noqa: E402
    ServiceAPIKeySerializer,
    AdminUserCreateRequestSerializer,
    AdminUserCreateResponseSerializer,
)
