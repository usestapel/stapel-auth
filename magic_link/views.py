"""Magic link views: request and verify login link endpoints."""

import logging

from django.contrib.auth import get_user_model
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import permissions
from rest_framework.viewsets import ViewSet
from stapel_core.django.errors import StapelErrorResponse, StapelResponse

from stapel_auth.errors import ERR_429_MAGIC_LINK_RATE
from stapel_auth.magic_link.serializers import (
    MagicLinkRequestBodySerializer,
    MagicLinkRequestResponseSerializer,
)
from stapel_auth.magic_link.services import MagicLinkService
from stapel_auth.mfa.services import TOTPService
from stapel_auth.sessions.services import AuditService
from stapel_auth.sessions.views import _add_login_hints, _issue_session_tokens
from stapel_auth.utils import SerializerSeamsMixin

_get_user_model = get_user_model

logger = logging.getLogger(__name__)


@extend_schema(tags=["Auth"])
class MagicLinkViewSet(SerializerSeamsMixin, ViewSet):
    permission_classes = [permissions.AllowAny]

    # Overridable serializer seams (see SerializerSeamsMixin).
    request_serializer_class = MagicLinkRequestBodySerializer
    response_serializer_class = MagicLinkRequestResponseSerializer

    @extend_schema(
        summary="Request a magic link login email",
        request=MagicLinkRequestBodySerializer,
        responses={200: MagicLinkRequestResponseSerializer},
    )
    def request_link(self, request):
        from .services import MagicLinkService

        ser = self.get_request_serializer_class()(data=request.data)
        ser.is_valid(raise_exception=True)
        email = ser.validated_data["email"].lower()
        redirect_url = ser.validated_data.get("redirect_url") or "/"
        U = _get_user_model()
        # Always return same response to not leak user existence
        try:
            user = U.objects.get(email=email, is_active=True)
            sent = MagicLinkService.send(
                user, request=request, redirect_url=redirect_url
            )
            if not sent:
                return StapelErrorResponse(429, ERR_429_MAGIC_LINK_RATE)
        except U.DoesNotExist:
            pass
        return StapelResponse(
            self.get_response_serializer_class()(
                {"message": "If this email is registered, a login link has been sent."}
            )
        )

    @extend_schema(
        summary="Verify a magic link token and issue session",
        parameters=[OpenApiParameter("token", str, required=True)],
        responses={302: None},
    )
    def verify(self, request):
        from django.shortcuts import redirect
        from stapel_core.django.utils import set_jwt_cookies

        from stapel_auth.conf import auth_settings

        frontend_url = auth_settings.FRONTEND_URL or ""

        token = request.query_params.get("token", "").strip()
        if not token:
            return redirect(f"{frontend_url}/login?error=invalid_link")

        # Peek without consuming — needed to handle already-authenticated cases
        peek = MagicLinkService.peek(token)
        if not peek:
            return redirect(f"{frontend_url}/login?error=invalid_link")

        if request.user.is_authenticated:
            if str(request.user.id) == str(peek.get("user_id")):
                # Same user already logged in — consume token, just redirect (no new session)
                MagicLinkService.consume(token)
                return redirect(peek.get("redirect_url") or "/")
            else:
                # Different user logged in — don't consume token, let them choose
                from urllib.parse import urlencode

                params = urlencode(
                    {"error": "account_conflict", "next": request.get_full_path()}
                )
                return redirect(f"{frontend_url}/login?{params}")

        data = MagicLinkService.consume(token)
        if not data:
            return redirect(f"{frontend_url}/login?error=invalid_link")

        U = _get_user_model()
        try:
            user = U.objects.get(id=data["user_id"], is_active=True)
        except U.DoesNotExist:
            return redirect(f"{frontend_url}/login?error=invalid_link")

        AuditService.log("magic_link_used", user=user, request=request)
        redirect_url = data.get("redirect_url") or "/"

        # If TOTP enabled — redirect to login page with TOTP challenge pre-loaded
        if getattr(user, "totp_enabled", False):
            challenge_token = TOTPService.create_challenge(str(user.id))
            from urllib.parse import urlencode

            params = urlencode(
                {"challenge_token": challenge_token, "next": redirect_url}
            )
            return redirect(f"{frontend_url}/login?{params}")

        access_token, refresh_token = _issue_session_tokens(user, request)
        response = redirect(redirect_url)
        set_jwt_cookies(response, access_token, refresh_token)
        return _add_login_hints(response)


# =============================================================================
# Suspicious login: "This wasn't me" revoke endpoint
# =============================================================================
