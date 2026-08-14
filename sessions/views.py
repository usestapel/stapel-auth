"""Session views: JWT token issuance and session management."""

import logging

from django.contrib.auth import authenticate, get_user_model
from drf_spectacular.utils import (
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from rest_framework import permissions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView
from stapel_core.django.errors import (
    StapelErrorResponse,
    StapelResponse,
)
from stapel_core.django.openapi import (
    StapelErrorSerializer,
)

from stapel_auth.conf import auth_settings
from stapel_auth.errors import *
from stapel_auth.sessions.dto import (
    TokenPairResponse,
)
from stapel_auth.sessions.guard import (
    SessionIssuanceDenied,
    SessionPath,
    session_precondition_error,
)
from stapel_auth.sessions.serializers import (
    SessionResponseSerializer,
    SimpleStatusSerializer,
    TokenPairSerializer,
)
from stapel_auth.utils import SerializerSeamsMixin

logger = logging.getLogger(__name__)
User = get_user_model()


# ── Sub-package cross-imports ─────────────────────────────────────────────────
from stapel_auth.models import UserSession
from stapel_auth.permissions import DenyEnrollOnly


@extend_schema(
    tags=["Token"],
    request=inline_serializer(
        name="TokenObtainRequest",
        fields={
            "username": serializers.CharField(help_text="Username or email"),
            "password": serializers.CharField(help_text="Password"),
        },
    ),
    responses={200: TokenPairSerializer, 401: StapelErrorSerializer},
)
class CustomTokenObtainPairView(SerializerSeamsMixin, APIView):
    """
    JWT token obtain view using unified jwt_provider.

    Accepts username/email and password, returns access and refresh tokens.
    """

    permission_classes = [permissions.AllowAny]

    # Overridable serializer seam (see SerializerSeamsMixin).
    response_serializer_class = TokenPairSerializer

    def post(self, request):
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from stapel_auth.hint_cookie import set_auth_hint_cookie

        # Accept both 'username' and 'email' as login field (for backwards compatibility)
        username = request.data.get("username") or request.data.get("email")
        password = request.data.get("password")

        if not username or not password:
            return StapelErrorResponse(400, ERR_400_CREDENTIALS_REQUIRED)

        # Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is None:
            # Try email authentication
            try:
                user_by_email = User.objects.get(email=username)
                user = authenticate(
                    request, username=user_by_email.username, password=password
                )
            except User.DoesNotExist:
                pass

        if user is None:
            return StapelErrorResponse(401, ERR_401_INVALID_CREDENTIALS)

        # One issuer for every full session (sessions/guard.py). This used to
        # run the admission predicate by hand and then mint directly, which
        # passed the gate but skipped everything else the choke-point does —
        # above all the tracked UserSession. An untracked session cannot be
        # listed, cannot be revoked, and is the precondition that made a
        # forged refresh token exploitable (audit AUTH-01/AUTH-02/AUTH-04).
        # The denial is raised, not returned: SessionIssuanceDenied renders
        # identically on every JSON path and carries the challenge_token, so
        # a flagged account can still finish the forced step.
        try:
            access_token, refresh_token = _issue_session_tokens(
                user, request, path=SessionPath.LEGACY_TOKEN
            )
        except SessionIssuanceDenied as denied:
            return StapelErrorResponse(
                denied.http_status, denied.error_key, denied.error_params
            )

        # Update last login
        from django.utils import timezone

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
        response = Response(
            self.get_response_serializer_class()(tokens_dto).data,
            status=status.HTTP_200_OK,
        )

        # Set cookies
        set_jwt_cookies(response, access_token, refresh_token)
        set_auth_hint_cookie(response)

        return response


@extend_schema_view(
    refresh_post=extend_schema(tags=["Token"]),
    refresh_get=extend_schema(tags=["Token"]),
)
class CustomTokenRefreshView(SerializerSeamsMixin, viewsets.GenericViewSet):
    """
    Custom token refresh view that checks refresh token from cookies/body
    and resets cookies with new access token
    """

    permission_classes = [permissions.AllowAny]

    # Overridable serializer seam (see SerializerSeamsMixin).
    response_serializer_class = TokenPairSerializer

    @extend_schema(
        description="Refresh access token using refresh token from cookies or request body",
        request=inline_serializer(
            name="TokenRefreshRequest",
            fields={
                "refresh": serializers.CharField(
                    required=False, help_text="Refresh token (optional if in cookies)"
                )
            },
        ),
        responses={200: TokenPairSerializer, 401: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="")
    def refresh_post(self, request):  # noqa: R007
        """POST endpoint to refresh access token"""
        return self._refresh_token(request)

    @extend_schema(
        description="Refresh access token using refresh token from cookies",
        responses={200: TokenPairSerializer, 401: StapelErrorSerializer},
    )
    @action(detail=False, methods=["get"], url_path="")
    def refresh_get(self, request):  # noqa: R007
        """GET endpoint to refresh access token"""
        return self._refresh_token(request)

    def _refresh_token(self, request):
        """Internal method to handle token refresh with rotation."""
        from stapel_core.django.jwt.provider import jwt_provider
        from stapel_core.django.jwt.utils import extract_jwt_from_request, set_jwt_cookies

        from stapel_auth.hint_cookie import set_auth_hint_cookie

        from .services import SessionService

        _, refresh_token_from_cookie = extract_jwt_from_request(request)
        refresh_token_from_body = (
            request.data.get("refresh") if request.method == "POST" else None
        )
        refresh_token = refresh_token_from_body or refresh_token_from_cookie

        if not refresh_token:
            return StapelErrorResponse(401, ERR_401_REFRESH_NOT_PROVIDED)

        # FULL cryptographic verification FIRST — signature, algorithm,
        # expiry, issuer and audience — before a single claim is read.
        # Reversing these two steps (decode with verify=False, trust user_id,
        # mint, validate afterwards) turned a JWT-shaped string with an
        # attacker-chosen user_id into a real token pair for that user
        # (audit AUTH-02). A claim from an unverified token is not data, it
        # is an argument supplied by the caller.
        _payload = jwt_provider.handler.decode_token(refresh_token)
        if not _payload:
            return StapelErrorResponse(401, ERR_401_REFRESH_INVALID)

        # A verified signature is not enough: an ACCESS token is signed by the
        # same key. Without this the shorter-lived, more widely exposed token
        # is a valid refresh credential.
        if _payload.get("token_type") != "refresh":
            return StapelErrorResponse(401, ERR_401_REFRESH_INVALID)

        if jwt_provider.is_blacklisted(refresh_token):
            return StapelErrorResponse(401, ERR_401_REFRESH_REVOKED)

        old_jti = _payload.get("jti")
        _uid = _payload.get("user_id")

        # A verified token with no jti names no session, so the rotation below
        # has nothing to bind it to — the same untracked state an unknown jti
        # lands in, and the same answer (audit AUTH-02). Every token this
        # library issues carries a jti; the branch exists so the absence
        # cannot become a quiet way around the session check.
        if not old_jti and not auth_settings.ALLOW_UNTRACKED_REFRESH:
            return StapelErrorResponse(401, ERR_401_REFRESH_INVALID)

        from stapel_core.django.jwt.authentication import is_user_blacklisted

        if _uid and is_user_blacklisted(_uid):
            logger.warning(f"Token refresh blocked: user {_uid} is blacklisted")
            return StapelErrorResponse(401, ERR_401_REFRESH_REVOKED)

        # Session-level check: reject revoked sessions
        if old_jti:
            from stapel_auth.models import UserSession

            session = UserSession.objects.filter(jti=old_jti).first()
            if session and session.is_revoked:
                return StapelErrorResponse(401, ERR_401_REFRESH_REVOKED)

        def load_user_data(user_id: str):
            try:
                user = User.objects.get(pk=user_id)
                # AS-2: fresh staff_roles claim on every refresh — this is
                # what bounds role-revocation latency by the access-token
                # lifetime (admin-suite A3).
                from stapel_auth.staff_roles import serialize_user_to_jwt_data

                return serialize_user_to_jwt_data(user)
            except User.DoesNotExist:
                return None

        # Issue new access token; jwt_provider also issues a new refresh token
        if old_jti:
            user_data = load_user_data(_uid)
            if not user_data:
                return StapelErrorResponse(401, ERR_401_REFRESH_INVALID)
            new_access_token, new_refresh_token = jwt_provider.create_tokens_from_data(
                user_data
            )
        else:
            new_access_token = jwt_provider.refresh_access_token(
                refresh_token, load_user_data
            )
            new_refresh_token = refresh_token

        if not new_access_token:
            return StapelErrorResponse(401, ERR_401_REFRESH_INVALID)

        # Rotate session: update jti to point at the new refresh token.
        # If no session record exists (legacy token pre-dating session tracking),
        # we allow the refresh through — only explicitly revoked sessions are denied.
        if old_jti and new_refresh_token != refresh_token:
            new_payload = (
                jwt_provider.handler.decode_token(new_refresh_token, verify=False) or {}
            )
            new_jti = new_payload.get("jti", "")
            import datetime

            from django.utils import timezone

            exp = new_payload.get("exp")
            expires_at = (
                datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
                if exp
                else timezone.now() + datetime.timedelta(days=7)
            )
            at_payload = (
                jwt_provider.handler.decode_token(new_access_token, verify=False) or {}
            )
            rotated = SessionService.rotate(
                old_jti,
                new_jti,
                expires_at,
                user_id=_uid,
                new_access_jti=at_payload.get("jti", ""),
            )
            if rotated is not True:
                # `False` means "no tracked session row for this jti". That
                # used to be accepted as a pre-session-tracking legacy token;
                # it is also exactly the state a forged jti lands in, so the
                # exception is opt-in and off by default (AUTH-02).
                if rotated is False and auth_settings.ALLOW_UNTRACKED_REFRESH:
                    logger.warning(
                        "Refreshing an untracked session for user %s — "
                        "STAPEL_AUTH['ALLOW_UNTRACKED_REFRESH'] is on",
                        _uid,
                    )
                else:
                    return StapelErrorResponse(401, ERR_401_REFRESH_REVOKED)
        else:
            new_refresh_token = refresh_token

        tokens_dto = TokenPairResponse(
            refresh=new_refresh_token, access=new_access_token
        )
        response = Response(
            self.get_response_serializer_class()(tokens_dto).data,
            status=status.HTTP_200_OK,
        )
        set_jwt_cookies(response, new_access_token, new_refresh_token)
        set_auth_hint_cookie(response)
        return response


_CH_HINTS = "Sec-CH-UA-Platform-Version, Sec-CH-UA-Model"


def _add_login_hints(response, *, critical: bool = False):
    """Append UA Client Hints headers so Chromium sends real OS/model on login."""
    response["Accept-CH"] = _CH_HINTS
    if critical:
        response["Critical-CH"] = _CH_HINTS
    return response


def _issue_session_tokens(
    user, request, *, path=SessionPath.UNSPECIFIED, audit_event="login_success"
):
    """Create a token pair, register a UserSession, return (access_str, refresh_str).

    THE session choke-point (org-program §P13): every path that hands out a
    *full* session goes through here, so this is where the "may this account
    be admitted at all" invariant is enforced — see
    :mod:`stapel_auth.sessions.guard`. Deliberately not in
    ``create_tokens_for_user``: that one is shared with the intermediate
    paths (forced change, MFA enroll exchange, SSO), which must stay outside
    the invariant or the user can never complete the very step they are held
    on.

    *path* is the :class:`~stapel_auth.sessions.guard.SessionPath` label of
    the caller; it selects the first-login gate scope and is the enumeration
    the gate's test suite walks. An undeclared caller fails closed.
    *audit_event* lets a path keep its own audit verb (SSO logs
    ``sso_login``) while still sharing this one body.

    Raises :class:`~stapel_auth.sessions.guard.SessionIssuanceDenied` — the
    stapel-core DRF handler renders it identically on every JSON path; the
    three browser-redirect paths catch it and build a front-end URL from
    ``requires``/``challenge_token`` instead.
    """
    import datetime

    from stapel_core.django.jwt.provider import jwt_provider

    from stapel_auth.staff_roles import create_tokens_for_user

    from .services import AuditService, LoginNotificationService, SessionService

    denied = session_precondition_error(user, path=path)
    if denied is not None:
        AuditService.log(
            "login_denied",
            user=user,
            request=request,
            reason=denied.error_key,
            path=path,
        )
        raise denied

    access_token, refresh_token = create_tokens_for_user(user)
    rt_payload = jwt_provider.handler.decode_token(refresh_token, verify=False) or {}
    at_payload = jwt_provider.handler.decode_token(access_token, verify=False) or {}
    jti = rt_payload.get("jti", "")
    exp = rt_payload.get("exp")
    expires_at = (
        datetime.datetime.fromtimestamp(exp, tz=datetime.timezone.utc)
        if exp
        else datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=7)
    )
    session = None
    if jti:
        session = SessionService.create(
            user, jti, expires_at, request=request, access_jti=at_payload.get("jti", "")
        )
    AuditService.log(audit_event, user=user, request=request, session=session)
    if session:
        LoginNotificationService.check_and_notify(user, session)
    return access_token, refresh_token


@extend_schema_view(
    list_sessions=extend_schema(tags=["Session"]),
    revoke_one=extend_schema(tags=["Session"]),
    confirm_session=extend_schema(tags=["Session"]),
    revoke_all=extend_schema(tags=["Session"]),
)
class SessionViewSet(SerializerSeamsMixin, viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated, DenyEnrollOnly]

    # Overridable serializer seams (see SerializerSeamsMixin).
    list_response_serializer_class = SessionResponseSerializer
    status_response_serializer_class = SimpleStatusSerializer

    @extend_schema(
        description="List all active sessions for the current user.",
        responses={200: SessionResponseSerializer(many=True)},
    )
    @action(detail=False, methods=["get"], url_path="")
    def list_sessions(self, request):  # noqa: R007
        from stapel_core.django.jwt.provider import jwt_provider

        from .services import SessionService

        # Determine current session jti from the access token
        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        current_jti = None
        if auth_header.startswith("Bearer "):
            payload = (
                jwt_provider.handler.decode_token(auth_header[7:], verify=False) or {}
            )
            current_jti = payload.get("refresh_jti") or payload.get("jti")

        from .dto import SessionResponse

        sessions = SessionService.get_active(request.user)
        dtos = [
            SessionResponse(
                id=str(s.id),
                device_type=s.device_type or "unknown",
                device_name=s.device_name or "Unknown device",
                device_details=s.device_details or "",
                ip_address=s.ip_address,
                created_at=s.created_at.isoformat(),
                last_used_at=s.last_used_at.isoformat(),
                is_current=s.jti == current_jti if current_jti else False,
                is_suspicious=s.is_suspicious,
            )
            for s in sessions
        ]
        return StapelResponse(
            self.get_list_response_serializer_class()(dtos, many=True)
        )

    @extend_schema(
        description="Revoke a specific session by ID.",
        responses={200: None, 404: StapelErrorSerializer},
    )
    @action(detail=False, methods=["delete"], url_path=r"(?P<session_id>[^/.]+)")
    def revoke_one(self, request, session_id=None):  # noqa: R007

        try:
            session = UserSession.objects.get(id=session_id, user=request.user)
        except UserSession.DoesNotExist:
            return StapelErrorResponse(404, ERR_404_NOT_FOUND)
        from .services import SessionService, _blacklist_jti

        # Flips is_revoked + writes the user.session_revoked outbox row
        # atomically (no-op if already revoked).
        SessionService.revoke_session(session)
        _blacklist_jti(session.jti, session.expires_at)
        _blacklist_jti(session.access_jti, session.expires_at)
        from stapel_auth.dto import SimpleStatusResponse

        return StapelResponse(
            self.get_status_response_serializer_class()(
                SimpleStatusResponse(status="revoked")
            )
        )

    @extend_schema(
        description='Mark a suspicious session as confirmed ("this was me"). Clears the suspicious flag.',
        request=None,
        responses={200: SimpleStatusSerializer, 404: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path=r"(?P<session_id>[^/.]+)/confirm")
    def confirm_session(self, request, session_id=None):  # noqa: R007
        try:
            session = UserSession.objects.get(
                id=session_id, user=request.user, is_revoked=False
            )
        except UserSession.DoesNotExist:
            return StapelErrorResponse(404, ERR_404_NOT_FOUND)
        if session.is_suspicious:
            session.is_suspicious = False
            session.save(update_fields=["is_suspicious"])
        from stapel_auth.dto import SimpleStatusResponse

        return StapelResponse(
            self.get_status_response_serializer_class()(
                SimpleStatusResponse(status="ok")
            )
        )

    @extend_schema(
        description="Revoke all sessions except the current one.",
        responses={200: None},
    )
    @action(detail=False, methods=["delete"], url_path="")
    def revoke_all(self, request):  # noqa: R007
        from stapel_core.django.jwt.provider import jwt_provider

        from .services import SessionService

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        current_jti = None
        if auth_header.startswith("Bearer "):
            payload = (
                jwt_provider.handler.decode_token(auth_header[7:], verify=False) or {}
            )
            current_jti = payload.get("refresh_jti") or payload.get("jti")

        SessionService.revoke_all(request.user, except_jti=current_jti)
        from stapel_auth.dto import SimpleStatusResponse

        return StapelResponse(
            self.get_status_response_serializer_class()(
                SimpleStatusResponse(status="revoked")
            )
        )


# =============================================================================
# Security Status ViewSet
# =============================================================================
