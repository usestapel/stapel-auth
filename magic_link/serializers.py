"""Magic link serializers."""

from rest_framework import serializers
from stapel_core.django.captcha import CaptchaMixin
from stapel_core.django.errors import StapelValidationError

from stapel_auth.errors import ERR_400_INVALID_REDIRECT_URL


class MagicLinkRequestBodySerializer(CaptchaMixin, serializers.Serializer):
    email = serializers.EmailField()
    redirect_url = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        default="/",
        help_text="Relative path to land on after login, e.g. /app or /meeting/abc. "
        "Must start with /. Absolute URLs are rejected.",
    )
    captcha_token = serializers.CharField(required=False, allow_blank=True)

    def validate_redirect_url(self, value):
        if not value or value == "/":
            return "/"
        # "//evil.com" and "/\\evil.com" are protocol-relative redirects --
        # only single-slash same-site paths are acceptable.
        if (
            not value.startswith("/")
            or value.startswith("//")
            or value.startswith("/\\")
        ):
            raise StapelValidationError(ERR_400_INVALID_REDIRECT_URL)
        return value

    def validate(self, attrs):
        self._require_captcha_if_configured(attrs)
        return attrs


class MagicLinkRequestResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class MagicLinkVerifyQuerySerializer(serializers.Serializer):
    token = serializers.CharField()
