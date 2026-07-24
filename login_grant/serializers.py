"""Login grant serializers."""

from rest_framework import serializers


class LoginGrantExchangeBodySerializer(serializers.Serializer):
    grant_token = serializers.CharField(
        help_text="Single-use grant token minted via the auth.issue_login_grant "
        "comm function (workspaces invitation claim flow).",
    )
