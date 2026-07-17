"""Views for the security sub-package: SecurityStatusViewSet, AuditLogViewSet, RevokeSuspiciousView."""

import logging

from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import permissions, viewsets
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework.viewsets import ViewSet
from stapel_core.django.api.errors import StapelErrorResponse, StapelResponse

from stapel_auth.errors import ERR_404_NOT_FOUND
from stapel_auth.security.serializers import (
    AdminAuditLogFilterSerializer,
    AuditLogFilterSerializer,
    AuditLogPageSerializer,
    SecurityStatusResponseSerializer,
)

logger = logging.getLogger(__name__)

User = None  # lazy import


def _get_user_model():
    from django.contrib.auth import get_user_model

    return get_user_model()


# =============================================================================
# Security Status ViewSet
# =============================================================================


class SecurityStatusViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        description="Return the full security posture for the current user. Used by the frontend to render the security settings screen.",
        tags=["Security"],
        responses={200: SecurityStatusResponseSerializer},
    )
    @action(detail=False, methods=["get"], url_path="")
    def status(self, request):  # noqa: R007
        from stapel_auth.models import PasskeyCredential
        from stapel_auth.security.dto import (
            SecurityStatusContact,
            SecurityStatusOAuth,
            SecurityStatusPasskeys,
            SecurityStatusPassword,
            SecurityStatusResponse,
            SecurityStatusSessions,
            SecurityStatusTOTP,
        )
        from stapel_auth.mfa.services import TOTPService
        from stapel_auth.sessions.services import SessionService

        user = request.user

        def mask_email(e):
            if not e:
                return None
            local, _, domain = e.partition("@")
            return local[:1] + "***@" + domain

        def mask_phone(p):
            if not p:
                return None
            return p[:3] + "***" + p[-2:]

        active_sessions = SessionService.get_active(user).count()
        totp_enabled = TOTPService.is_enabled(user)
        backup_remaining = TOTPService.backup_codes_remaining(user)
        passkey_count = PasskeyCredential.objects.filter(
            user=user, is_active=True
        ).count()

        from stapel_auth.models import LinkedOAuthAccount

        connected_oauth = []
        if user.oauth_provider:
            connected_oauth.append(user.oauth_provider)
        connected_oauth.extend(
            LinkedOAuthAccount.objects.filter(user=user)
            .exclude(provider=user.oauth_provider)
            .values_list("provider", flat=True)
        )

        dto = SecurityStatusResponse(
            password=SecurityStatusPassword(is_set=user.has_usable_password()),
            totp=SecurityStatusTOTP(
                is_enabled=totp_enabled, backup_codes_remaining=backup_remaining
            ),
            email=SecurityStatusContact(
                value=mask_email(user.email), is_verified=user.is_email_verified
            ),
            phone=SecurityStatusContact(
                value=mask_phone(user.phone), is_verified=user.is_phone_verified
            ),
            oauth=SecurityStatusOAuth(connected_providers=connected_oauth),
            sessions=SecurityStatusSessions(active_count=active_sessions),
            passkeys=SecurityStatusPasskeys(count=passkey_count),
        )
        return StapelResponse(SecurityStatusResponseSerializer(dto))


# =============================================================================
# Audit Log
# =============================================================================


@extend_schema(tags=["Security"])
class AuditLogViewSet(ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        summary="List security audit log",
        responses={200: AuditLogPageSerializer},
        parameters=[
            OpenApiParameter("event_type", str, required=False),
            OpenApiParameter(
                "date_from",
                str,
                required=False,
                description="ISO date, e.g. 2026-01-01",
            ),
            OpenApiParameter(
                "date_to", str, required=False, description="ISO date, e.g. 2026-12-31"
            ),
            OpenApiParameter("page", int, required=False),
        ],
    )
    def get_log(self, request):
        from stapel_auth.models import AuthAuditLog

        PAGE_SIZE = 20

        filter_ser = AuditLogFilterSerializer(data=request.query_params)
        filter_ser.is_valid(raise_exception=True)
        filters = filter_ser.validated_data

        page = filters.get("page", 1)
        offset = (page - 1) * PAGE_SIZE

        qs = AuthAuditLog.objects.filter(user=request.user)
        if event_type := filters.get("event_type"):
            qs = qs.filter(event_type=event_type)
        if date_from := filters.get("date_from"):
            qs = qs.filter(created_at__date__gte=date_from)
        if date_to := filters.get("date_to"):
            qs = qs.filter(created_at__date__lte=date_to)

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
# Admin audit log (staff/superuser sees all users)
# =============================================================================


@extend_schema(tags=["Admin"])
class AdminAuditLogViewSet(ViewSet):
    permission_classes = [permissions.IsAdminUser]

    @extend_schema(
        summary="List audit log entries for all users (admin only)",
        responses={200: AuditLogPageSerializer},
        parameters=[
            OpenApiParameter("user_id", str, required=False),
            OpenApiParameter("event_type", str, required=False),
            OpenApiParameter("date_from", str, required=False, description="ISO date"),
            OpenApiParameter("date_to", str, required=False, description="ISO date"),
            OpenApiParameter("page", int, required=False),
        ],
    )
    def list_logs(self, request):
        from stapel_auth.models import AuthAuditLog

        PAGE_SIZE = 50

        filter_ser = AdminAuditLogFilterSerializer(data=request.query_params)
        filter_ser.is_valid(raise_exception=True)
        filters = filter_ser.validated_data

        page = filters.get("page", 1)
        offset = (page - 1) * PAGE_SIZE

        qs = AuthAuditLog.objects.select_related("user", "session")
        if user_id := filters.get("user_id"):
            qs = qs.filter(user_id=user_id)
        if event_type := filters.get("event_type"):
            qs = qs.filter(event_type=event_type)
        if date_from := filters.get("date_from"):
            qs = qs.filter(created_at__date__gte=date_from)
        if date_to := filters.get("date_to"):
            qs = qs.filter(created_at__date__lte=date_to)

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
    def get(self, request):  # noqa: R007
        from django.core.signing import BadSignature, SignatureExpired, TimestampSigner
        from stapel_core.notifications import request_notification

        from stapel_auth.models import AuthEventType
        from stapel_auth.sessions.services import AuditService

        token = request.query_params.get("token", "")
        signer = TimestampSigner()
        try:
            value = signer.unsign(token, max_age=7 * 24 * 3600)
        except (BadSignature, SignatureExpired):
            from stapel_auth.conf import auth_settings

            frontend_url = auth_settings.FRONTEND_URL or ""
            from django.shortcuts import redirect

            return redirect(f"{frontend_url}/login?error=invalid_link")

        user_id, session_id = value.split(":", 1)
        U = _get_user_model()
        try:
            user = U.objects.get(id=user_id)
        except U.DoesNotExist:
            return StapelErrorResponse(404, ERR_404_NOT_FOUND)

        # Service path: revokes atomically with the user.session_revoked
        # outbox events and blacklists the live JTIs (the raw .update() here
        # skipped both).
        from stapel_auth.sessions.services import SessionService

        SessionService.revoke_all(user)
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

        from stapel_auth.conf import auth_settings

        frontend_url = auth_settings.FRONTEND_URL or ""
        from django.shortcuts import redirect

        return redirect(f"{frontend_url}/login?notice=sessions_revoked")
