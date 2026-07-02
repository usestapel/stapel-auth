"""
Views for security phase 3 features: Audit Log, Magic Links, Passkeys.
"""

import json
import logging

from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import permissions, serializers
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet
from stapel_core.django.api.errors import StapelErrorResponse, StapelResponse

from .errors import (
    ERR_400_LAST_AUTH_METHOD,
    ERR_400_PASSKEY_CHALLENGE_EXPIRED,
    ERR_400_PASSKEY_INVALID,
    ERR_404_NOT_FOUND,
    ERR_404_PASSKEY_NOT_FOUND,
    ERR_429_MAGIC_LINK_RATE,
)
from .serializers import AuthResponseSerializer

logger = logging.getLogger(__name__)

User = None  # lazy import


def _get_user_model():
    from django.contrib.auth import get_user_model

    return get_user_model()


# =============================================================================
# Serializers (inline for new features — no separate serializers.py changes yet)
# =============================================================================


class AuditLogEntrySerializer(serializers.Serializer):
    id = serializers.CharField()
    event_type = serializers.CharField()
    ip_address = serializers.CharField(allow_null=True)
    user_agent = serializers.CharField()
    metadata = serializers.DictField()
    created_at = serializers.DateTimeField()


class MagicLinkRequestBodySerializer(serializers.Serializer):
    email = serializers.EmailField()
    redirect_url = serializers.CharField(
        required=False,
        allow_blank=True,
        allow_null=True,
        default="/",
        help_text="Relative path to land on after login, e.g. /app or /meeting/abc. "
        "Must start with /. Absolute URLs are rejected.",
    )

    def validate_redirect_url(self, value):
        if not value or value == "/":
            return "/"
        if not value.startswith("/"):
            raise serializers.ValidationError("redirect_url must start with /.")
        return value


class MagicLinkRequestResponseSerializer(serializers.Serializer):
    message = serializers.CharField()


class AuditLogPageSerializer(serializers.Serializer):
    results = AuditLogEntrySerializer(many=True)
    count = serializers.IntegerField()
    next = serializers.IntegerField(allow_null=True)


class PasskeyItemSerializer(serializers.Serializer):
    id = serializers.CharField()
    device_name = serializers.CharField()
    aaguid = serializers.CharField()
    transports = serializers.ListField(child=serializers.CharField())
    created_at = serializers.DateTimeField()
    last_used_at = serializers.DateTimeField(allow_null=True)


class PasskeyListResponseSerializer(serializers.Serializer):
    passkeys = PasskeyItemSerializer(many=True)


class PasskeyRegOptionsSerializer(serializers.Serializer):
    options = serializers.DictField()


class PasskeyAuthOptionsSerializer(serializers.Serializer):
    session_key = serializers.CharField()
    options = serializers.DictField()


class MagicLinkVerifyQuerySerializer(serializers.Serializer):
    token = serializers.CharField()


class PasskeyRegisterCompleteBodySerializer(serializers.Serializer):
    credential = serializers.JSONField()
    device_name = serializers.CharField(required=False, default="", allow_blank=True)


class PasskeyAuthBeginBodySerializer(serializers.Serializer):
    email = serializers.EmailField(required=False, allow_null=True, default=None)


class PasskeyAuthCompleteBodySerializer(serializers.Serializer):
    session_key = serializers.CharField()
    credential = serializers.JSONField()


# =============================================================================
# Audit Log
# =============================================================================


@extend_schema(tags=["Security"])
class AuditLogViewSet(ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="List security audit log",
        responses={200: AuditLogPageSerializer},
        parameters=[OpenApiParameter("page", int, required=False)],
    )
    def get_log(self, request):
        from .models import AuthAuditLog

        PAGE_SIZE = 20
        page = max(1, int(request.query_params.get("page", 1)))
        offset = (page - 1) * PAGE_SIZE
        qs = AuthAuditLog.objects.filter(user=request.user).select_related()
        total = qs.count()
        entries = qs[offset : offset + PAGE_SIZE]
        entry_data = [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "ip_address": e.ip_address,
                "user_agent": e.user_agent,
                "metadata": e.metadata,
                "created_at": e.created_at,
            }
            for e in entries
        ]
        return StapelResponse(
            AuditLogPageSerializer(
                {
                    "results": entry_data,
                    "count": total,
                    "next": page + 1 if offset + PAGE_SIZE < total else None,
                }
            )
        )


# =============================================================================
# Magic Links
# =============================================================================


@extend_schema(tags=["Auth"])
class MagicLinkViewSet(ViewSet):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Request a magic link login email",
        request=MagicLinkRequestBodySerializer,
        responses={200: MagicLinkRequestResponseSerializer},
    )
    def request_link(self, request):
        from .services import MagicLinkService

        ser = MagicLinkRequestBodySerializer(data=request.data)
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
            MagicLinkRequestResponseSerializer(
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
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from .conf import auth_settings
        from .services import AuditService, MagicLinkService, TOTPService
        from .views import _add_login_hints, _issue_session_tokens

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


@extend_schema(tags=["Security"])
class RevokeSuspiciousView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Revoke all sessions via suspicious login email link",
        parameters=[OpenApiParameter("token", str, required=True)],
        responses={302: None},
    )
    def get(self, request):
        from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
        from stapel_core.notifications import request_notification

        from .models import AuthEventType, UserSession
        from .services import AuditService

        token = request.query_params.get("token", "")
        signer = TimestampSigner()
        try:
            value = signer.unsign(token, max_age=7 * 24 * 3600)
        except (BadSignature, SignatureExpired):
            from .conf import auth_settings

            frontend_url = auth_settings.FRONTEND_URL or ""
            from django.shortcuts import redirect

            return redirect(f"{frontend_url}/login?error=invalid_link")

        user_id, session_id = value.split(":", 1)
        U = _get_user_model()
        try:
            user = U.objects.get(id=user_id)
        except U.DoesNotExist:
            return StapelErrorResponse(404, ERR_404_NOT_FOUND)

        UserSession.objects.filter(user=user, is_revoked=False).update(is_revoked=True)
        AuditService.log(
            AuthEventType.SESSION_REVOKE_ALL,
            user=user,
            request=request,
            triggered_by="suspicious_login_report",
        )

        if user.email:
            try:
                request_notification(
                    notification_type="all_sessions_revoked",
                    user_id=str(user.id),
                    email=user.email,
                    variables={},
                    source_service="auth",
                )
            except Exception:
                logger.exception("Failed to send all_sessions_revoked notification")

        from .conf import auth_settings

        frontend_url = auth_settings.FRONTEND_URL or ""
        from django.shortcuts import redirect

        return redirect(f"{frontend_url}/login?notice=sessions_revoked")


# =============================================================================
# Passkeys
# =============================================================================


@extend_schema(tags=["Passkeys"])
class PasskeyViewSet(ViewSet):
    _anon_actions = frozenset({"auth_begin", "auth_complete"})

    def get_permissions(self):
        if self.action in self._anon_actions:
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()]

    @extend_schema(
        summary="List registered passkeys",
        responses={200: PasskeyListResponseSerializer},
    )
    def get_list(self, request):
        from .models import PasskeyCredential

        qs = PasskeyCredential.objects.filter(
            user=request.user, is_active=True
        ).order_by("-created_at")
        data = [_pc_to_dict(pc) for pc in qs]
        return StapelResponse(PasskeyListResponseSerializer({"passkeys": data}))

    @extend_schema(summary="Remove a passkey", responses={204: None})
    def destroy(self, request, pk=None):
        from .models import PasskeyCredential

        try:
            pc = PasskeyCredential.objects.get(id=pk, user=request.user, is_active=True)
        except PasskeyCredential.DoesNotExist:
            return StapelErrorResponse(404, ERR_404_PASSKEY_NOT_FOUND)

        # Require at least one other auth method
        user = request.user
        has_password = bool(
            getattr(user, "password", None) and user.password not in ("", "!")
        )
        has_totp = getattr(user, "totp_enabled", False)
        other_passkeys = (
            PasskeyCredential.objects.filter(user=user, is_active=True)
            .exclude(id=pk)
            .exists()
        )
        if not (has_password or has_totp or other_passkeys):
            return StapelErrorResponse(400, ERR_400_LAST_AUTH_METHOD)

        pc.is_active = False
        pc.save(update_fields=["is_active"])
        from .services import AuditService

        AuditService.log("passkey_removed", user=user, device_name=pc.device_name)
        return StapelResponse(status=204)

    @extend_schema(
        summary="Begin passkey registration (generate options)",
        responses={200: PasskeyRegOptionsSerializer},
    )
    def register_begin(self, request):
        from .services import PasskeyService

        try:
            options_json = PasskeyService.registration_begin(request.user)
        except Exception:
            logger.exception("passkey register_begin failed")
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)
        options = (
            json.loads(options_json) if isinstance(options_json, str) else options_json
        )
        return StapelResponse(PasskeyRegOptionsSerializer({"options": options}))

    @extend_schema(
        summary="Complete passkey registration",
        request=PasskeyRegisterCompleteBodySerializer,
        responses={200: PasskeyItemSerializer},
    )
    def register_complete(self, request):
        from .services import PasskeyService

        ser = PasskeyRegisterCompleteBodySerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            pc = PasskeyService.registration_complete(
                request.user,
                ser.validated_data["credential"],
                device_name=ser.validated_data.get("device_name", ""),
            )
        except ValueError as exc:
            code = str(exc)
            if code == "challenge_expired":
                return StapelErrorResponse(400, ERR_400_PASSKEY_CHALLENGE_EXPIRED)
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)
        except Exception:
            logger.exception("passkey register_complete failed")
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)
        return StapelResponse(PasskeyItemSerializer(_pc_to_dict(pc)))

    @extend_schema(
        summary="Begin passkey authentication",
        request=PasskeyAuthBeginBodySerializer,
        responses={200: PasskeyAuthOptionsSerializer},
    )
    def auth_begin(self, request):
        from .services import PasskeyService

        ser = PasskeyAuthBeginBodySerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user = None
        email = ser.validated_data.get("email")
        if email:
            U = _get_user_model()
            try:
                user = U.objects.get(email=email, is_active=True)
            except U.DoesNotExist:
                pass
        try:
            session_key, options_json = PasskeyService.authentication_begin(user)
        except Exception:
            logger.exception("passkey auth_begin failed")
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)
        options = (
            json.loads(options_json) if isinstance(options_json, str) else options_json
        )
        return StapelResponse(
            PasskeyAuthOptionsSerializer(
                {"session_key": session_key, "options": options}
            )
        )

    @extend_schema(
        summary="Complete passkey authentication and issue session",
        request=PasskeyAuthCompleteBodySerializer,
        responses={200: AuthResponseSerializer},
    )
    def auth_complete(self, request):
        from stapel_auth.views import _issue_session_tokens

        from .services import PasskeyService

        ser = PasskeyAuthCompleteBodySerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            user, pc = PasskeyService.authentication_complete(
                ser.validated_data["session_key"],
                ser.validated_data["credential"],
            )
        except ValueError as exc:
            code = str(exc)
            if code == "challenge_expired":
                return StapelErrorResponse(400, ERR_400_PASSKEY_CHALLENGE_EXPIRED)
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)
        except Exception:
            logger.exception("passkey auth_complete failed")
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)

        access_token, refresh_token = _issue_session_tokens(user, request)
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from .dto import AuthResponse, AuthStatus, TokenPairResponse
        from .views import _add_login_hints

        dto = AuthResponse(
            status=AuthStatus.LOGGED_IN,
            user=user,
            tokens=TokenPairResponse(refresh=refresh_token, access=access_token),
        )
        response = StapelResponse(AuthResponseSerializer(dto))
        set_jwt_cookies(response, access_token, refresh_token)
        return _add_login_hints(response)


def _pc_to_dict(pc):
    return {
        "id": str(pc.id),
        "device_name": pc.device_name,
        "aaguid": pc.aaguid,
        "transports": pc.transports or [],
        "created_at": pc.created_at,
        "last_used_at": pc.last_used_at,
    }
