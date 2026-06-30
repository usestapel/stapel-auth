"""Serializers for the admin sub-package."""
from rest_framework import serializers
from stapel_core.django.api.serializers import IronDataclassSerializer
from stapel_core.django.api.errors import IronValidationError

from stapel_auth.models import ServiceAPIKey
from stapel_auth.errors import ERR_400_EMAIL_OR_PHONE_REQUIRED
from stapel_auth.admin.dto import AdminUserCreateResponse


def _normalize_phone(value):
    """Parse and normalize phone number to E.164 format (+79991234567)."""
    import phonenumbers
    from stapel_auth.errors import (
        ERR_400_INVALID_PHONE_FORMAT,
        ERR_400_INVALID_PHONE,
        ERR_400_PHONE_TOO_LONG,
    )
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


class ServiceAPIKeySerializer(serializers.ModelSerializer):
    """Serializer for Service API Keys"""

    class Meta:
        model = ServiceAPIKey
        fields = ['id', 'name', 'key', 'description', 'is_active', 'created_at', 'last_used_at', 'allowed_endpoints']
        read_only_fields = ['id', 'key', 'created_at', 'last_used_at']


class AdminUserCreateRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_null=True, default=None)
    phone = serializers.CharField(required=False, allow_null=True, default=None)
    username = serializers.CharField(required=False, allow_null=True, default=None)
    display_name = serializers.CharField(required=False, allow_null=True, default=None)
    password = serializers.CharField(required=False, allow_null=True, default=None, min_length=8)
    send_welcome = serializers.BooleanField(default=False)
    mark_verified = serializers.BooleanField(default=True)

    def validate(self, attrs):
        if not any([attrs.get("email"), attrs.get("phone"), attrs.get("username")]):
            raise IronValidationError(ERR_400_EMAIL_OR_PHONE_REQUIRED)
        if attrs.get("phone"):
            attrs["phone"] = _normalize_phone(attrs["phone"])
        return attrs


class AdminUserCreateResponseSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = AdminUserCreateResponse
