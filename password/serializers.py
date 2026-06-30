"""Serializers for the password authentication domain."""
from rest_framework import serializers
from stapel_core.django.api.serializers import IronDataclassSerializer
from stapel_core.django.api.errors import IronValidationError
from stapel_core.django.captcha import CaptchaMixin
from django.contrib.auth.password_validation import validate_password

from stapel_auth.errors import (
    ERR_400_INVALID_PHONE_FORMAT, ERR_400_INVALID_PHONE, ERR_400_PHONE_TOO_LONG,
    ERR_400_PASSWORDS_DONT_MATCH,
)
from stapel_auth.password.dto import (
    PasswordMethod,
    PasswordMethodsResponse,
    PasswordMethodType,
)


def normalize_phone(value):
    """Parse and normalize phone number to E.164 format (+79991234567)."""
    import phonenumbers
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


class PasswordResetEmailRequestSerializer(CaptchaMixin, serializers.Serializer):
    email = serializers.EmailField()
    captcha_token = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        self._require_captcha_if_configured(attrs)
        return attrs


class PasswordResetEmailVerifySerializer(serializers.Serializer):
    email = serializers.EmailField()
    code = serializers.CharField(max_length=4)
    new_password = serializers.CharField(min_length=8)

    def validate_new_password(self, value):
        validate_password(value)
        return value


class PasswordResetPhoneRequestSerializer(CaptchaMixin, serializers.Serializer):
    phone = serializers.CharField()
    captcha_token = serializers.CharField(required=False, allow_blank=True)

    def validate_phone(self, value):
        return normalize_phone(value)

    def validate(self, attrs):
        self._require_captcha_if_configured(attrs)
        return attrs


class PasswordResetPhoneVerifySerializer(serializers.Serializer):
    phone = serializers.CharField()
    code = serializers.CharField(max_length=4)
    new_password = serializers.CharField(min_length=8)

    def validate_phone(self, value):
        return normalize_phone(value)

    def validate_new_password(self, value):
        validate_password(value)
        return value


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


class PasswordMethodSerializer(IronDataclassSerializer):
    class Meta:
        dataclass = PasswordMethod


class PasswordMethodsResponseSerializer(IronDataclassSerializer):
    methods = PasswordMethodSerializer(many=True)

    class Meta:
        dataclass = PasswordMethodsResponse


class PasswordRegisterSerializer(CaptchaMixin, serializers.Serializer):
    password = serializers.CharField(min_length=8, write_only=True)
    email = serializers.EmailField(required=False, allow_null=True, default=None)
    phone = serializers.CharField(required=False, allow_null=True, default=None)
    username = serializers.CharField(required=False, allow_null=True, default=None)
    captcha_token = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        if not any([attrs.get("email"), attrs.get("phone"), attrs.get("username")]):
            from stapel_auth.errors import ERR_400_EMAIL_OR_PHONE_REQUIRED
            raise IronValidationError(ERR_400_EMAIL_OR_PHONE_REQUIRED)
        if attrs.get("phone"):
            attrs["phone"] = normalize_phone(attrs["phone"])
        self._require_captcha_if_configured(attrs)
        return attrs
