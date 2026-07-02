"""Serializers for QR auth domain."""

from rest_framework import serializers
from stapel_core.django.api.errors import StapelValidationError
from stapel_core.django.api.serializers import StapelDataclassSerializer

from stapel_auth.errors import ERR_400_INVALID_REDIRECT_URL
from stapel_auth.qr.dto import QRGenerateResponse, QRStatusResponse, QRType


class QRGenerateSerializer(serializers.Serializer):
    type = serializers.ChoiceField(
        choices=[e.value for e in QRType],
        help_text=(
            "`session_share` — logged-in user generates a QR to share their session with a scanner (e.g. log into a new device). Requires auth. "
            "`login_request` — unauthenticated device generates a QR and waits for a logged-in scanner to approve the login."
        ),
    )
    redirect_url = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        default=None,
        help_text=(
            "Where to redirect the scanner after successful auth. "
            "Must be a relative path starting with / (e.g. /home). "
            "For `session_share`: the scanning device lands here after receiving the session. "
            "For `login_request`: the confirming device lands here after approving. "
            "Defaults to `/` if omitted."
        ),
    )

    allow_unauthenticated_scanner = serializers.BooleanField(
        required=False,
        default=False,
        help_text=(
            "`session_share` only: explicitly allow a scanner with no session "
            "to receive the owner's session. Default false — an "
            "unauthenticated scan of a session_share QR is rejected with 403."
        ),
    )

    def validate_redirect_url(self, value):
        if not value:
            return value
        # Reject protocol-relative ("//evil.com") and backslash variants --
        # only single-slash same-site paths.
        if (
            value.startswith("/")
            and not value.startswith("//")
            and not value.startswith("/\\")
        ):
            return value
        raise StapelValidationError(ERR_400_INVALID_REDIRECT_URL)


class QRGenerateResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = QRGenerateResponse


class QRStatusResponseSerializer(StapelDataclassSerializer):
    class Meta:
        dataclass = QRStatusResponse
