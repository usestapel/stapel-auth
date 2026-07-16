"""Serializers for OAuth authentication and auth capabilities."""
from rest_framework import serializers
from stapel_core.django.api.serializers import StapelDataclassSerializer
from stapel_auth.oauth.dto import (
    OAuthProviderInfo,
    RegistrationCapabilities,
    LoginCapabilities,
    MFACapabilities,
    AuthMethodInfo,
    OtpMeta,
    AuthCapabilities,
    LinkedOAuthAccountDTO,
    OAuthLinksResponse,
)


class OAuthSerializer(serializers.Serializer):
    """Serializer for OAuth authentication"""
    provider = serializers.CharField(max_length=50)
    access_token = serializers.CharField(max_length=500)


class OAuthProviderInfoSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = OAuthProviderInfo


class RegistrationCapabilitiesSerializer(StapelDataclassSerializer):
    oauth = OAuthProviderInfoSerializer(many=True)

    class Meta:
        dataclass = RegistrationCapabilities


class LoginCapabilitiesSerializer(StapelDataclassSerializer):
    oauth = OAuthProviderInfoSerializer(many=True)

    class Meta:
        dataclass = LoginCapabilities


class MFACapabilitiesSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = MFACapabilities


class AuthMethodInfoSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = AuthMethodInfo


class OtpMetaSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = OtpMeta


class AuthCapabilitiesSerializer(StapelDataclassSerializer):
    registration = RegistrationCapabilitiesSerializer()
    login = LoginCapabilitiesSerializer()
    mfa = MFACapabilitiesSerializer()
    methods = AuthMethodInfoSerializer(many=True)
    otp = OtpMetaSerializer()

    class Meta:
        dataclass = AuthCapabilities


# ── OAuth account links (security-profile inventory) ────────────────────────

class LinkedOAuthAccountSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = LinkedOAuthAccountDTO


class OAuthLinksResponseSerializer(StapelDataclassSerializer):
    links = LinkedOAuthAccountSerializer(many=True)

    class Meta:
        dataclass = OAuthLinksResponse


class OAuthLinkRequestSerializer(serializers.Serializer):
    """Body for POST /oauth/links/ — same shape as OAuthSerializer (the login
    request), reusing the client-side OAuth exchange already in place: the
    frontend runs the provider's OAuth flow and hands us the resulting
    access_token, which we verify server-side via the provider before linking.
    """
    provider = serializers.CharField(max_length=50)
    access_token = serializers.CharField(max_length=500)
