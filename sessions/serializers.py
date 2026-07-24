"""Serializers for the sessions sub-package."""
from rest_framework import serializers
from drf_spectacular.utils import PolymorphicProxySerializer
from stapel_core.django.api.serializers import StapelDataclassSerializer

from .dto import (
    TokenPairResponse,
    AuthResponse,
    TokenVerifyResponse,
    LogoutResponse,
    SessionResponse,
)

# UserSerializer lives at the top level — import it to avoid duplication
from django.contrib.auth import get_user_model
from stapel_auth.mfa.serializers import TOTPChallengeResponseSerializer

_User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = _User
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


class TokenPairSerializer(StapelDataclassSerializer):
    """Serializer for JWT token pair."""
    class Meta:
        dataclass = TokenPairResponse


class AuthResponseSerializer(StapelDataclassSerializer):
    """Serializer for authentication response with user and tokens."""
    user = UserSerializer(read_only=True)

    class Meta:
        dataclass = AuthResponse


class TokenVerifyResponseSerializer(StapelDataclassSerializer):
    """Serializer for token verify response."""
    user = UserSerializer()

    class Meta:
        dataclass = TokenVerifyResponse


class TokenVerifySerializer(serializers.Serializer):
    """Serializer for token verification"""
    token = serializers.CharField()


class LogoutResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = LogoutResponse


# Polymorphic union: password login / oauth login return either a full
# AuthResponse (status=LOGGED_IN/REGISTERED), a TOTPChallengeResponse
# (status=TOTP_REQUIRED), or — org-provisioned accounts with a first-login
# policy flag (workspaces-org-program §C2) — a FirstLoginChallengeResponse
# (status=FIRST_LOGIN_REQUIRED). The `status` field is the discriminator.
# drf-spectacular emits oneOf + discriminator so API generators produce
# a proper TypeScript union with type narrowing.
#
# NOTE: AuthResponseSerializer is also needed by otp/views.py and other
# sub-packages; keep it importable from both here and the top-level serializers.py.
from stapel_auth.password.serializers import FirstLoginChallengeResponseSerializer  # noqa: E402

LoginResponseSerializer = PolymorphicProxySerializer(
    component_name='LoginResponse',
    serializers=[
        AuthResponseSerializer,
        TOTPChallengeResponseSerializer,
        FirstLoginChallengeResponseSerializer,
    ],
    resource_type_field_name='status',
)


class SessionResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = SessionResponse


from stapel_auth.dto import SimpleStatusResponse


class SimpleStatusSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = SimpleStatusResponse


# Polymorphic union: PasswordViewSet.change_otp_verify returns either a plain
# SimpleStatusResponse (ordinary password change — no promotion, no user
# change) or a full User-bearing AuthResponse (the caller was an anonymous
# guest session and the contact OTP verification promoted it — the client's
# session.adopt() needs the `user` to flip anon -> registered). See
# password/services.py PasswordService.change_via_otp and
# password/views.py PasswordViewSet.change_otp_verify.
PasswordOtpChangeResponseSerializer = PolymorphicProxySerializer(
    component_name='PasswordOtpChangeResponse',
    serializers=[AuthResponseSerializer, SimpleStatusSerializer],
    resource_type_field_name='status',
)
