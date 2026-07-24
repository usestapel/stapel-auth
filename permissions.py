from rest_framework import permissions
from django.utils import timezone
from .models import ServiceAPIKey
import logging

logger = logging.getLogger(__name__)


# ── Enroll-only sessions (workspaces-org-program §C2) ────────────────────────
#
# The first-login mfa_enroll intermediate mints a LIMITED access token with
# the JWT claim ``enroll_only`` (see mfa.views.MfaEnrollViewSet.exchange).
# Auth has no scope machinery, so the restriction is expressed the DRF way:
# ``DenyEnrollOnly`` rides in ``permission_classes`` of every authenticated
# view (AND-composed after IsAuthenticated), with a central allowlist of the
# only actions an enroll session may perform — TOTP setup/confirm, passkey
# registration, and logout.

#: (view class name, viewset action) pairs an enroll-only session may call.
ENROLL_ONLY_ALLOWED_ACTIONS = frozenset({
    ("TOTPViewSet", "setup"),
    ("TOTPViewSet", "confirm_setup"),
    ("PasskeyViewSet", "register_begin"),
    ("PasskeyViewSet", "register_complete"),
    ("AuthViewSet", "logout"),
    ("AuthViewSet", "logout_get"),
})


def is_enroll_only_request(request) -> bool:
    """Whether the request authenticated with an ``enroll_only`` token.

    Reads the claim from the access token the (already-run) authentication
    layer validated — the signature was verified there, so a plain decode
    suffices here; a request that failed authentication never gets past
    ``IsAuthenticated`` to a decision that depends on this claim.
    """
    from stapel_core.django.jwt.provider import jwt_provider
    from stapel_core.django.jwt.utils import extract_jwt_from_request

    try:
        access_token, _ = extract_jwt_from_request(request)
        if not access_token:
            return False
        payload = jwt_provider.handler.decode_token(access_token, verify=False) or {}
    except Exception:
        # An unreadable/undecodable token cannot be an enroll session (and
        # it never authenticated either) — the guard must not preempt the
        # view's own error handling with a 500 from check_permissions.
        return False
    return bool(payload.get("enroll_only"))


class DenyEnrollOnly(permissions.BasePermission):
    """Deny enroll-only sessions everywhere except the enrollment surface.

    Passes silently for normal sessions. For an ``enroll_only`` token it
    consults :data:`ENROLL_ONLY_ALLOWED_ACTIONS` and otherwise raises the
    structured 403 ``error.403.mfa_enrollment_required`` (via
    StapelServiceError → stapel_exception_handler), telling the client
    exactly why the surface is closed.
    """

    def has_permission(self, request, view):
        if not is_enroll_only_request(request):
            return True
        key = (type(view).__name__, getattr(view, "action", None))
        if key in ENROLL_ONLY_ALLOWED_ACTIONS:
            return True
        from stapel_core.django.api.errors import StapelServiceError

        from .errors import ERR_403_MFA_ENROLLMENT_REQUIRED

        raise StapelServiceError(403, ERR_403_MFA_ENROLLMENT_REQUIRED)


class IsServiceAPIKey(permissions.BasePermission):
    """
    Permission class to check if request has valid service API key
    """

    def has_permission(self, request, view):
        # Check for API key in header
        api_key = request.headers.get('x-api-key')

        if not api_key:
            return False

        try:
            service_key = ServiceAPIKey.objects.get(key=api_key, is_active=True)

            # Update last used timestamp
            service_key.last_used_at = timezone.now()
            service_key.save(update_fields=['last_used_at'])

            # Attach service to request for later use
            request.service = service_key

            return True
        except ServiceAPIKey.DoesNotExist:
            logger.warning(f"Invalid API key attempt: {api_key[:10]}...")
            return False


class IsInternalService(permissions.BasePermission):
    """
    Permission class for internal service-to-service communication
    """

    def has_permission(self, request, view):
        from django.conf import settings

        # Check for internal service key
        internal_key = request.headers.get('x-internal-service-key')

        if not internal_key:
            return False

        if internal_key == settings.INTERNAL_SERVICE_KEY:
            return True

        logger.warning("Invalid internal service key attempt")
        return False


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Object-level permission to only allow owners of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed to any request
        if request.method in permissions.SAFE_METHODS:
            return True

        # Write permissions are only allowed to the owner
        return obj.user == request.user
