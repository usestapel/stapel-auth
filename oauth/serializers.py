"""Serializers for OAuth authentication and auth capabilities."""
from rest_framework import serializers
from stapel_core.django.api.serializers import StapelDataclassSerializer
from stapel_auth.oauth.dto import (
    OAuthProviderInfo,
    RegistrationCapabilities,
    LoginCapabilities,
    MFACapabilities,
    AuthCapabilities,
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


class AuthCapabilitiesSerializer(StapelDataclassSerializer):
    registration = RegistrationCapabilitiesSerializer()
    login = LoginCapabilitiesSerializer()
    mfa = MFACapabilitiesSerializer()

    class Meta:
        dataclass = AuthCapabilities
