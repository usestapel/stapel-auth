"""Backward-compatibility shim — imports from sub-packages."""
from django.contrib.auth import get_user_model
from rest_framework import serializers
from stapel_core.django.api.serializers import IronDataclassSerializer

from .dto import SimpleStatusResponse
from stapel_auth.sessions.serializers import AuthResponseSerializer, LoginResponseSerializer  # noqa: F401
from stapel_auth.otp.serializers import (  # noqa: F401
    OtpSentResponseSerializer,
    PhoneAuthRequestSerializer,
    ConvertAnonymousUserSerializer,
    InstantChangeRequestNewSerializer,
    DelayedChangeInitiateSerializer,
    DelayedChangeCancelSerializer,
)
from stapel_auth.mfa.serializers import TOTPChallengeResponseSerializer  # noqa: F401
from stapel_auth.oauth.serializers import AuthCapabilitiesSerializer  # noqa: F401

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

# ── Sessions serializers ──────────────────────────────────────────────────────

# ── OTP serializers ───────────────────────────────────────────────────────────

# ── OAuth serializers ─────────────────────────────────────────────────────────

# ── Password serializers ──────────────────────────────────────────────────────

# ── MFA (TOTP + Passkey) serializers ─────────────────────────────────────────

# ── QR serializers ────────────────────────────────────────────────────────────

# ── Security serializers ──────────────────────────────────────────────────────

# ── Admin serializers ─────────────────────────────────────────────────────────
