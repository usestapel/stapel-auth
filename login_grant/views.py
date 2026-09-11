"""Login grant views: exchange a grant token for a JWT session (§B3)."""

import logging

from drf_spectacular.utils import extend_schema
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.viewsets import ViewSet
from stapel_core.django.errors import StapelErrorResponse, StapelErrorSerializer

from stapel_auth.errors import ERR_400_GRANT_INVALID, ERR_403_GRANT_EXISTING_ACCOUNT
from stapel_auth.login_grant.serializers import LoginGrantExchangeBodySerializer
from stapel_auth.login_grant.services import (
    ExistingAccountRefused,
    ExistingAccountStepUp,
    LoginGrantService,
)
from stapel_auth.mfa.dto import TOTPChallengeResponse, TOTPChallengeStatus
from stapel_auth.mfa.serializers import TOTPChallengeResponseSerializer
from stapel_auth.mfa.services import TOTPService
from stapel_auth.sessions.dto import AuthResponse, AuthStatus, TokenPairResponse
from stapel_auth.sessions.serializers import AuthResponseSerializer
from stapel_auth.sessions.services import AuditService
from stapel_auth.sessions.guard import SessionPath
from stapel_auth.sessions.views import _add_login_hints, _issue_session_tokens
from stapel_auth.utils import SerializerSeamsMixin

logger = logging.getLogger(__name__)


@extend_schema(tags=["Auth"])
class LoginGrantViewSet(SerializerSeamsMixin, ViewSet):
    permission_classes = [permissions.AllowAny]

    # Overridable serializer seams (see SerializerSeamsMixin).
    request_serializer_class = LoginGrantExchangeBodySerializer
    response_serializer_class = AuthResponseSerializer
    totp_challenge_response_serializer_class = TOTPChallengeResponseSerializer

    @extend_schema(
        summary="Exchange a login grant token for a JWT session",
        description=(
            "Consumes a single-use login grant (minted service-side via the "
            "auth.issue_login_grant comm function — the workspaces invitation "
            "claim flow) and issues a full JWT session. When the grant was "
            "minted with create_if_missing and no account exists for its "
            "email, a verified email account is created "
            "(status=REGISTERED instead of LOGGED_IN).\n\n"
            "What an address that ALREADY has a full account gets is the "
            "deployment's AUTH_LOGIN_GRANT_EXISTING_ACCOUNTS policy: 'login' "
            "(the default, a session), 'refuse' "
            "(403 error.403.grant_existing_account) or 'step_up' "
            "(TOTPChallengeResponse, status=TOTP_REQUIRED — pass "
            "challenge_token to POST /totp/challenge/verify/)."
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

        try:
            result = LoginGrantService.exchange(token)
        except ExistingAccountRefused:
            # The grant was fine; the address already has an account this
            # deployment does not hand to a grant. A different answer from a
            # spent token on purpose — the holder signs in instead.
            return StapelErrorResponse(403, ERR_403_GRANT_EXISTING_ACCOUNT)
        except ExistingAccountStepUp as step_up:
            challenge_token = TOTPService.create_challenge(str(step_up.user.id))
            dto = TOTPChallengeResponse(
                status=TOTPChallengeStatus.TOTP_REQUIRED,
                challenge_token=challenge_token,
                expires_in=TOTPService.CHALLENGE_TTL,
            )
            return Response(
                self.get_totp_challenge_response_serializer_class()(dto).data,
                status=status.HTTP_200_OK,
            )
        if result is None:
            return StapelErrorResponse(400, ERR_400_GRANT_INVALID)
        user, created = result

        AuditService.log("login_grant_used", user=user, request=request)
        access_token, refresh_token = _issue_session_tokens(user, request, path=SessionPath.LOGIN_GRANT)
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
