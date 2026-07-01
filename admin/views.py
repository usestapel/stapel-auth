"""Views for the admin sub-package: ServiceAPIKeyViewSet, AdminUserViewSet, CapabilitiesView."""

import logging

from drf_spectacular.utils import extend_schema
from rest_framework import permissions, viewsets
from rest_framework.decorators import action
from rest_framework.views import APIView
from stapel_core.django.api.errors import (
    StapelResponse,
)

from stapel_auth.admin.dto import AdminUserCreateResponse
from stapel_auth.admin.serializers import (
    AdminUserCreateRequestSerializer,
    AdminUserCreateResponseSerializer,
    ServiceAPIKeySerializer,
)
from stapel_auth.models import ServiceAPIKey

logger = logging.getLogger(__name__)


@extend_schema(tags=["API Keys"])
class ServiceAPIKeyViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing service API keys
    """

    queryset = ServiceAPIKey.objects.all()
    serializer_class = ServiceAPIKeySerializer
    permission_classes = [permissions.IsAdminUser]

    def perform_create(self, serializer):
        """Generate API key on creation"""
        serializer.save(key=ServiceAPIKey.generate_key())


class CapabilitiesView(APIView):
    """Public endpoint returning enabled auth methods for this deployment."""

    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    @extend_schema(
        tags=["Auth"],
        description="Return available authentication and registration methods for this deployment.",
        responses={200: None},
    )
    def get(self, request):
        from stapel_auth.oauth.services import AuthCapabilitiesService
        from stapel_auth.serializers import AuthCapabilitiesSerializer

        caps = AuthCapabilitiesService.get_capabilities()
        return StapelResponse(AuthCapabilitiesSerializer(caps))


# ── Admin User Broker ─────────────────────────────────────────────────────────


class AdminUserViewSet(viewsets.GenericViewSet):
    """Admin broker for creating users without OTP verification."""

    permission_classes = [permissions.AllowAny]

    @extend_schema(
        tags=["Admin"],
        description="Create a user account without OTP, bypassing normal registration flow. Requires service API key or admin (staff) credentials.",
        request=AdminUserCreateRequestSerializer,
        responses={201: AdminUserCreateResponseSerializer, 400: None, 403: None},
    )
    @action(detail=False, methods=["post"])
    def create_user(self, request):
        from django.contrib.auth import get_user_model
        from stapel_core.django.api.errors import error_403_forbidden

        from stapel_auth.permissions import IsServiceAPIKey

        User = get_user_model()

        # Allow either staff user or service API key
        is_svc_key = IsServiceAPIKey().has_permission(request, self)
        if not is_svc_key and not (
            request.user.is_authenticated and request.user.is_staff
        ):
            return error_403_forbidden()

        serializer = AdminUserCreateRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        email = data.get("email")
        phone = data.get("phone")
        username = data.get("username")
        display_name = data.get("display_name")
        password = data.get("password")
        mark_verified = data.get("mark_verified", True)
        send_welcome = data.get("send_welcome", False)

        user = User.objects.create(
            email=email,
            phone=phone,
            username=username or (email.split("@")[0] if email else phone),
            is_email_verified=mark_verified and bool(email),
            is_phone_verified=mark_verified and bool(phone),
        )
        if display_name:
            user.first_name = display_name
        if password:
            user.set_password(password)
        user.save()

        if send_welcome:
            try:
                from stapel_core.notifications import request_notification

                request_notification(notification_type="welcome", user_id=str(user.id))
            except Exception:
                logger.exception(
                    "Failed to send welcome notification for user %s", user.id
                )

        dto = AdminUserCreateResponse(
            user_id=str(user.id),
            email=user.email,
            phone=user.phone,
            username=user.username,
        )
        return StapelResponse(AdminUserCreateResponseSerializer(dto), status=201)
