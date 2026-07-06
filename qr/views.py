"""Views for QR auth domain."""

import logging

from django.urls import reverse
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import permissions, status, viewsets
from rest_framework.decorators import action
from stapel_core.django.api.errors import StapelErrorResponse, StapelResponse
from stapel_core.django.openapi.schemas import StapelErrorSerializer

from stapel_auth.errors import (
    ERR_400_QR_FULFILLED,
    ERR_400_QR_TYPE_REQUIRED,
    ERR_401_QR_AUTH_REQUIRED,
    ERR_404_QR_NOT_FOUND,
)
from stapel_auth.qr.dto import QRGenerateResponse, QRStatus, QRStatusResponse, QRType
from stapel_auth.qr.serializers import (
    QRGenerateResponseSerializer,
    QRGenerateSerializer,
    QRStatusResponseSerializer,
)
from stapel_auth.qr.services import QRAuthService
from stapel_auth.serializers import SimpleStatusSerializer
from stapel_auth.sessions.services import (
    AuditService,
    LoginNotificationService,
    SessionService,
)
from stapel_auth.sessions.views import _issue_session_tokens
from stapel_auth.utils import SerializerSeamsMixin

logger = logging.getLogger(__name__)


# ── QR Auth ViewSet ───────────────────────────────────────────────────────────


@extend_schema_view(
    generate=extend_schema(tags=["QR Auth"]),
    qr_status=extend_schema(tags=["QR Auth"]),
    scan=extend_schema(tags=["QR Auth"]),
    confirm=extend_schema(tags=["QR Auth"]),
)
class QRAuthViewSet(SerializerSeamsMixin, viewsets.GenericViewSet):
    permission_classes = [permissions.AllowAny]

    # Overridable serializer seams (see SerializerSeamsMixin).
    generate_request_serializer_class = QRGenerateSerializer
    generate_response_serializer_class = QRGenerateResponseSerializer
    status_response_serializer_class = QRStatusResponseSerializer
    simple_status_response_serializer_class = SimpleStatusSerializer

    _authenticated_actions = frozenset({"confirm"})

    def get_permissions(self):
        if self.action in self._authenticated_actions:
            return [permissions.IsAuthenticated()]
        return [permissions.AllowAny()]

    QR_TTL = QRAuthService.TTL

    @extend_schema(
        description="""Generate a short-lived QR auth key (5 min TTL).

**Types:**
- `session_share` — a logged-in device generates a QR; when another device scans it, that device receives the same session. Requires authentication.
- `login_request` — an unauthenticated device generates a QR and polls for approval; a logged-in scanner confirms the login.

**`redirect_url`** (optional) — where to send the scanner after the auth flow completes. Defaults to `/`.

**Response:** encode `scan_url` into a QR image (e.g. via qrcode.js) and display it. Poll `GET /qr/{key}/status/` to know when the flow completes.
""",
        request=QRGenerateSerializer,
        responses={
            201: QRGenerateResponseSerializer,
            400: StapelErrorSerializer,
            401: StapelErrorSerializer,
        },
    )
    @action(detail=False, methods=["post"], url_path="generate")
    def generate(self, request):
        import secrets as _secrets

        serializer = self.get_generate_request_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        qr_type = serializer.validated_data["type"]
        redirect_url = serializer.validated_data.get("redirect_url")
        allow_unauth = serializer.validated_data.get(
            "allow_unauthenticated_scanner", False
        )

        if qr_type == QRType.SESSION_SHARE and not request.user.is_authenticated:
            return StapelErrorResponse(401, ERR_401_QR_AUTH_REQUIRED)

        owner_user_id = request.user.id if request.user.is_authenticated else None
        # Bind the QR to the generating device: the nonce travels back only
        # as an httponly cookie, so another device polling a stolen key can
        # never present it.
        nonce = _secrets.token_urlsafe(32)
        key = QRAuthService.generate(
            qr_type=qr_type,
            owner_user_id=owner_user_id,
            redirect_url=redirect_url,
            nonce=nonce,
            allow_unauthenticated_scanner=allow_unauth,
        )

        # reverse() follows whatever prefix this URLconf is mounted under
        # (STAPEL_MOUNTS / include()), so the scan URL never hardcodes the
        # historical "/auth/api/" mount point and stays correct under any mount.
        scan_url = request.build_absolute_uri(reverse("qr_scan", kwargs={"key": key}))
        dto = QRGenerateResponse(
            key=key,
            type=qr_type,
            expires_in=self.QR_TTL,
            scan_url=scan_url,
        )
        response = StapelResponse(
            self.get_generate_response_serializer_class()(dto),
            status=status.HTTP_201_CREATED,
        )
        response.set_cookie(
            self._nonce_cookie_name(key),
            nonce,
            max_age=self.QR_TTL,
            httponly=True,
            secure=request.is_secure(),
            samesite="Lax",
            path="/",
        )
        return response

    @staticmethod
    def _nonce_cookie_name(key: str) -> str:
        return f"stapel_qr_{key}"

    @classmethod
    def _nonce_matches(cls, request, key: str, data: dict) -> bool:
        """Constant-time check of the device-binding cookie against the QR record."""
        import hmac as _hmac

        expected = data.get("nonce")
        if not expected:
            # Legacy record without a nonce (created before upgrade) — allow.
            return True
        presented = request.COOKIES.get(cls._nonce_cookie_name(key), "")
        return _hmac.compare_digest(str(presented), str(expected))

    @extend_schema(
        description="""Poll the status of a QR auth key.

**Statuses:**
- `pending` — waiting for scan/confirm.
- `fulfilled` — action completed; for `login_request`, tokens are included so the polling device can authenticate.
- `expired` — key was not found (TTL elapsed).
- `rejected` — scanner or confirmer rejected the request; show error UI.
""",
        responses={200: QRStatusResponseSerializer},
    )
    @action(detail=False, methods=["get"], url_path=r"(?P<key>[^/.]+)/status")
    def qr_status(self, request, key=None):
        from stapel_auth.errors import ERR_403_QR_DEVICE_MISMATCH

        data = QRAuthService.get(key)
        if data is None:
            dto = QRStatusResponse(status=QRStatus.EXPIRED)
            return StapelResponse(self.get_status_response_serializer_class()(dto))

        # login_request status polling hands out session tokens once
        # fulfilled — only the device that generated the QR (and thus holds
        # the httponly nonce cookie) may claim them.
        if data["type"] == QRType.LOGIN_REQUEST and not self._nonce_matches(
            request, key, data
        ):
            return StapelErrorResponse(403, ERR_403_QR_DEVICE_MISMATCH)

        if data["status"] == QRStatus.REJECTED:
            return StapelResponse(
                self.get_status_response_serializer_class()(
                    QRStatusResponse(status=QRStatus.REJECTED)
                )
            )

        if data["status"] == QRStatus.FULFILLED:
            access_token = data.get("access_token")
            refresh_token = data.get("refresh_token")
            # Create session for the polling device (once — key is deleted after)
            if access_token and data.get("fulfilled_user_id"):
                try:
                    from datetime import datetime
                    from datetime import timezone as _tz

                    from django.contrib.auth import get_user_model as _gum
                    from stapel_core.django.jwt.provider import jwt_provider as _jwt

                    _rt = data.get("refresh_token", "")
                    _rt_pl = _jwt.handler.decode_token(_rt, verify=False) or {}
                    _at_pl = _jwt.handler.decode_token(access_token, verify=False) or {}
                    _jti = _rt_pl.get("jti", "")
                    _exp = datetime.fromtimestamp(_rt_pl.get("exp", 0), tz=_tz.utc)
                    _user = _gum().objects.filter(pk=data["fulfilled_user_id"]).first()
                    if _user and _jti:
                        _session = SessionService.create(
                            _user,
                            _jti,
                            _exp,
                            request=request,
                            access_jti=_at_pl.get("jti", ""),
                        )
                        AuditService.log(
                            "login_success",
                            user=_user,
                            request=request,
                            session=_session,
                        )
                        if _session:
                            LoginNotificationService.check_and_notify(_user, _session)
                except Exception:
                    pass
                QRAuthService.delete(key)
            dto = QRStatusResponse(
                status=QRStatus.FULFILLED,
                access_token=access_token,
                refresh_token=refresh_token,
            )
        else:
            dto = QRStatusResponse(status=QRStatus.PENDING)

        return StapelResponse(self.get_status_response_serializer_class()(dto))

    @extend_schema(
        description="""Browser endpoint embedded in QR code. Processes the scan and redirects.

**session_share** (scanner has no session) → logs scanner in as the QR owner and redirects to `redirect_url`.
**session_share** (scanner already logged in as the same user) → marks fulfilled, redirects.
**session_share** (scanner logged in as a *different* user) → redirects with `?qr_status=account_conflict`.
**login_request** (scanner logged in) → redirects to `/qr-confirm?key=…` for confirmation.
**login_request** (scanner not logged in) → redirects to `/sign-in?redirect=<scan_url>`.
""",
        responses={302: None, 404: StapelErrorSerializer},
    )
    @action(detail=False, methods=["get"], url_path=r"(?P<key>[^/.]+)/scan")
    def scan(self, request, key=None):
        from urllib.parse import urlencode

        from django.contrib.auth import get_user_model as _get_user_model
        from django.http import HttpResponseRedirect
        from stapel_core.django.jwt.utils import set_jwt_cookies

        data = QRAuthService.get(key)
        if data is None:
            return StapelErrorResponse(404, ERR_404_QR_NOT_FOUND)
        if data["status"] == QRStatus.FULFILLED:
            return StapelErrorResponse(400, ERR_400_QR_FULFILLED)

        qr_type = data["type"]
        redirect_url = data.get("redirect_url") or "/"
        scanner = request.user if request.user.is_authenticated else None

        if qr_type == QRType.SESSION_SHARE:
            _User = _get_user_model()
            try:
                owner = _User.objects.get(pk=data["owner_user_id"])
            except _User.DoesNotExist:
                return StapelErrorResponse(404, ERR_404_QR_NOT_FOUND)

            if scanner is None:
                # Handing the owner's session to an anonymous scanner is
                # account takeover by QR swap — only allowed when the QR was
                # created with explicit allow_unauthenticated_scanner.
                if not data.get("allow_unauthenticated_scanner"):
                    from stapel_auth.errors import ERR_403_QR_UNAUTH_SCAN

                    return StapelErrorResponse(403, ERR_403_QR_UNAUTH_SCAN)
                # Issue tokens for the owner and log in the scanner
                QRAuthService.fulfill_session_share(key, scanner_user_id=owner.id)
                access_token, refresh_token = _issue_session_tokens(owner, request)
                response = HttpResponseRedirect(redirect_url)
                set_jwt_cookies(response, access_token, refresh_token)
                return response

            if str(scanner.id) == str(owner.id):
                # Same user already logged in — no new session, just redirect
                QRAuthService.fulfill_session_share(key, scanner_user_id=scanner.id)
                return HttpResponseRedirect(redirect_url)

            # Different user — mark QR rejected, let the generator know, redirect scanner to conflict
            QRAuthService.reject(key)
            from django.conf import settings as _s

            _frontend = getattr(_s, "FRONTEND_URL", "https://app.example.com")
            from urllib.parse import urlencode as _ue

            return HttpResponseRedirect(
                f"{_frontend}/login?{_ue({'error': 'account_conflict'})}"
            )

        else:  # login_request
            if scanner is None:
                scan_url = request.build_absolute_uri()
                sign_in_url = "/sign-in?" + urlencode({"redirect": scan_url})
                return HttpResponseRedirect(sign_in_url)

            # Logged-in scanner → confirm page
            confirm_url = "/qr-confirm?" + urlencode({"key": key})
            return HttpResponseRedirect(confirm_url)

    @extend_schema(
        description="Reject a QR auth request. The device polling `/status` will receive `rejected`.",
        request=None,
        responses={200: SimpleStatusSerializer, 404: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path=r"(?P<key>[^/.]+)/reject")
    def reject(self, request, key=None):
        data = QRAuthService.get(key)
        if data is None:
            return StapelErrorResponse(404, ERR_404_QR_NOT_FOUND)
        QRAuthService.reject(key)
        from stapel_auth.dto import SimpleStatusResponse

        return StapelResponse(
            self.get_simple_status_response_serializer_class()(
                SimpleStatusResponse(status="rejected")
            )
        )

    @extend_schema(
        description="""Confirm a `login_request` QR code (called by the logged-in scanner after reviewing).

Issues tokens for the waiting device. The device polling `/status` will receive the tokens.
""",
        request=None,
        responses={
            200: SimpleStatusSerializer,
            400: StapelErrorSerializer,
            401: StapelErrorSerializer,
            404: StapelErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path=r"(?P<key>[^/.]+)/confirm",
        permission_classes=[permissions.IsAuthenticated],
    )
    def confirm(self, request, key=None):
        from stapel_core.django.jwt.provider import jwt_provider

        data = QRAuthService.get(key)
        if data is None:
            return StapelErrorResponse(404, ERR_404_QR_NOT_FOUND)
        if data["status"] != QRStatus.PENDING:
            return StapelErrorResponse(400, ERR_400_QR_FULFILLED)
        if data["type"] != QRType.LOGIN_REQUEST:
            return StapelErrorResponse(400, ERR_400_QR_TYPE_REQUIRED)

        access_token, refresh_token = jwt_provider.create_tokens(request.user)
        QRAuthService.fulfill_login_request(
            key,
            approver_user_id=request.user.id,
            access_token=access_token,
            refresh_token=refresh_token,
        )
        from stapel_auth.dto import SimpleStatusResponse

        return StapelResponse(
            self.get_simple_status_response_serializer_class()(
                SimpleStatusResponse(status="confirmed")
            )
        )
