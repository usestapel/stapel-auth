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
    StaffRoleAssignmentSerializer,
    StaffRoleAssignRequestSerializer,
)
from stapel_auth.oauth.serializers import AuthCapabilitiesSerializer
from stapel_auth.models import ServiceAPIKey, StaffRoleAssignment
from stapel_auth.permissions import DenyEnrollOnly

logger = logging.getLogger(__name__)


@extend_schema(tags=["API Keys"])
class ServiceAPIKeyViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing service API keys
    """

    queryset = ServiceAPIKey.objects.all()
    serializer_class = ServiceAPIKeySerializer
    permission_classes = [permissions.IsAdminUser, DenyEnrollOnly]

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
        responses={200: AuthCapabilitiesSerializer},
    )
    def get(self, request):  # noqa: R007
        from stapel_auth.oauth.services import AuthCapabilitiesService

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
    def create_user(self, request):  # noqa: R007
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


# ── Staff roles (admin-suite AS-2) ────────────────────────────────────────────


class StaffRoleViewSet(viewsets.GenericViewSet):
    """Manage staff role assignments — the auth service is the single writer
    of user → role mappings (admin-suite invariant A2).

    Gating: staff + the corresponding Django model permission on
    ``StaffRoleAssignment``. With the AS-1 mandate backends configured this
    resolves to clearance HIGH (the model is declared all-HIGH); without
    them it falls back to superuser / explicit DAC grants — never to plain
    staff. Writes go through ``stapel_auth.staff_roles`` services, so every
    change emits its ``staff.role.assigned`` / ``staff.role.revoked`` audit
    event through the outbox.
    """

    permission_classes = [permissions.IsAdminUser, DenyEnrollOnly]
    queryset = StaffRoleAssignment.objects.all()
    serializer_class = StaffRoleAssignmentSerializer

    _PERM_BY_ACTION = {
        "list_assignments": "view",
        "assign": "add",
        "revoke": "delete",
    }

    def _permitted(self, request) -> bool:
        op = self._PERM_BY_ACTION[self.action]
        return request.user.has_perm(f"authentication.{op}_staffroleassignment")

    @extend_schema(
        tags=["Staff Roles"],
        description=(
            "List staff role assignments, optionally filtered by ?user_id=. "
            "Requires the view permission on StaffRoleAssignment "
            "(clearance HIGH under the mandate)."
        ),
        responses={200: StaffRoleAssignmentSerializer(many=True), 403: None},
    )
    @action(detail=False, methods=["get"])
    def list_assignments(self, request):  # noqa: R007
        from stapel_core.django.api.errors import error_403_forbidden

        if not self._permitted(request):
            return error_403_forbidden()
        qs = self.get_queryset().order_by("user_id", "role_name")
        user_id = request.query_params.get("user_id")
        if user_id:
            qs = qs.filter(user_id=user_id)
        return StapelResponse(StaffRoleAssignmentSerializer(qs, many=True))

    @extend_schema(
        tags=["Staff Roles"],
        description=(
            "Assign a staff role (a name from the STAPEL_ACCESS['ROLES'] "
            "registry) to a staff user. Idempotent: 201 on a new assignment, "
            "200 when it already existed. Emits staff.role.assigned."
        ),
        request=StaffRoleAssignRequestSerializer,
        responses={201: StaffRoleAssignmentSerializer, 400: None, 403: None, 404: None},
    )
    @action(detail=False, methods=["post"])
    def assign(self, request):  # noqa: R007
        from django.contrib.auth import get_user_model
        from stapel_core.django.api.errors import (
            StapelErrorResponse,
            error_403_forbidden,
        )

        from stapel_auth.errors import (
            ERR_400_STAFF_ROLE_TARGET_NOT_STAFF,
            ERR_400_UNKNOWN_STAFF_ROLE,
            ERR_404_NOT_FOUND,
        )
        from stapel_auth.staff_roles import (
            StaffRoleTargetNotStaffError,
            UnknownStaffRoleError,
            assign_staff_role,
        )

        if not self._permitted(request):
            return error_403_forbidden()

        serializer = StaffRoleAssignRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        User = get_user_model()
        target = User.objects.filter(pk=data["user_id"]).first()
        if target is None:
            return StapelErrorResponse(404, ERR_404_NOT_FOUND)

        try:
            assignment, created = assign_staff_role(
                target, data["role"], assigned_by=request.user
            )
        except UnknownStaffRoleError:
            return StapelErrorResponse(400, ERR_400_UNKNOWN_STAFF_ROLE)
        except StaffRoleTargetNotStaffError:
            return StapelErrorResponse(400, ERR_400_STAFF_ROLE_TARGET_NOT_STAFF)

        return StapelResponse(
            StaffRoleAssignmentSerializer(assignment),
            status=201 if created else 200,
        )

    @extend_schema(
        tags=["Staff Roles"],
        description=(
            "Revoke a staff role assignment by its id. "
            "Emits staff.role.revoked."
        ),
        responses={204: None, 403: None, 404: None},
    )
    @action(detail=True, methods=["delete"])
    def revoke(self, request, assignment_id=None):  # noqa: R007
        from stapel_core.django.api.errors import (
            StapelErrorResponse,
            error_403_forbidden,
        )

        from stapel_auth.errors import ERR_404_NOT_FOUND
        from stapel_auth.staff_roles import revoke_staff_role

        if not self._permitted(request):
            return error_403_forbidden()

        assignment = StaffRoleAssignment.objects.filter(pk=assignment_id).first()
        if assignment is None:
            return StapelErrorResponse(404, ERR_404_NOT_FOUND)

        revoke_staff_role(
            assignment.user, assignment.role_name, revoked_by=request.user
        )
        return StapelResponse(status=204)
