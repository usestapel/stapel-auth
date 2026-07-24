"""Login grant views: exchange a grant token for a JWT session (§B3)."""

import logging

from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from stapel_core.django.errors import StapelErrorResponse, StapelErrorSerializer

from stapel_auth.errors import ERR_400_GRANT_INVALID
from stapel_auth.login_grant.serializers import LoginGrantExchangeBodySerializer
from stapel_auth.login_grant.services import LoginGrantService
from stapel_auth.sessions.dto import AuthResponse, AuthStatus, TokenPairResponse
from stapel_auth.sessions.serializers import AuthResponseSerializer
from stapel_auth.sessions.services import AuditService
from stapel_auth.sessions.views import _add_login_hints, _issue_session_tokens
from stapel_auth.utils import SerializerSeamsMixin

logger = logging.getLogger(__name__)


@extend_schema(tags=["Auth"])
class LoginGrantViewSet(SerializerSeamsMixin, ViewSet):
    permission_classes = [permissions.AllowAny]

    # Overridable serializer seams (see SerializerSeamsMixin).
    request_serializer_class = LoginGrantExchangeBodySerializer
    response_serializer_class = AuthResponseSerializer

    @extend_schema(
        summary="Exchange a login grant token for a JWT session",
        description=(
            "Consumes a single-use login grant (minted service-side via the "
            "auth.issue_login_grant comm function — the workspaces invitation "
            "claim flow) and issues a full JWT session. When the grant was "
            "minted with create_if_missing and no account exists for its "
            "email, a verified email account is created "
            "(status=REGISTERED instead of LOGGED_IN)."
        ),
        request=LoginGrantExchangeBodySerializer,
        responses={
            200: AuthResponseSerializer,
            400: StapelErrorSerializer,
            403: StapelErrorSerializer,
        },
    )
    def exchange(self, request):
        from stapel_core.django.errors import error_403_forbidden
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from stapel_auth.conf import auth_settings
        from stapel_auth.hint_cookie import set_auth_hint_cookie

        if not auth_settings.AUTH_LOGIN_GRANT:
            return error_403_forbidden()

        ser = self.get_request_serializer_class()(data=request.data)
        ser.is_valid(raise_exception=True)
        token = ser.validated_data["grant_token"].strip()

        result = LoginGrantService.exchange(token)
        if result is None:
            return StapelErrorResponse(400, ERR_400_GRANT_INVALID)
        user, created = result

        AuditService.log("login_grant_used", user=user, request=request)
        access_token, refresh_token = _issue_session_tokens(user, request)
        tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
        auth_dto = AuthResponse(
            status=AuthStatus.REGISTERED if created else AuthStatus.LOGGED_IN,
            user=user,
            tokens=tokens_dto,
        )
        response = Response(
            self.get_response_serializer_class()(auth_dto).data,
            status=status.HTTP_200_OK,
        )
        set_jwt_cookies(response, access_token, refresh_token)
        set_auth_hint_cookie(response)
        return _add_login_hints(response)
