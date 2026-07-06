"""Views for the password authentication domain."""

import logging

from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework import permissions, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from stapel_core.django.api.errors import (
    ERR_400_BAD_REQUEST,
    StapelErrorResponse,
    StapelResponse,
)
from stapel_core.django.openapi.schemas import StapelErrorSerializer

from stapel_auth.dto import (
    AuthResponse,
    AuthStatus,
    OtpSentResponse,
    TokenPairResponse,
    TOTPChallengeResponse,
    TOTPChallengeStatus,
)
from stapel_auth.errors import (
    ERR_400_NO_PASSWORD,
    ERR_400_WRONG_PASSWORD,
    ERR_401_ACCOUNT_DISABLED,
    ERR_401_INVALID_CREDENTIALS,
    ERR_409_EMAIL_TAKEN,
    ERR_409_PHONE_TAKEN,
    ERR_409_USERNAME_TAKEN,
)
from stapel_auth.password.dto import PasswordMethodsResponse
from stapel_auth.password.serializers import (
    PasswordChangeDirectSerializer,
    PasswordLoginSerializer,
    PasswordMethodsResponseSerializer,
    PasswordOtpRequestSerializer,
    PasswordOtpVerifySerializer,
    PasswordRegisterSerializer,
    PasswordResetEmailRequestSerializer,
    PasswordResetEmailVerifySerializer,
    PasswordResetPhoneRequestSerializer,
    PasswordResetPhoneVerifySerializer,
)
from stapel_auth.password.services import PasswordService
from stapel_auth.serializers import (
    AuthResponseSerializer,
    LoginResponseSerializer,
    OtpSentResponseSerializer,
    SimpleStatusSerializer,
    TOTPChallengeResponseSerializer,
)
from stapel_auth.sessions.views import _add_login_hints, _issue_session_tokens
from stapel_auth.utils import SerializerSeamsMixin

logger = logging.getLogger(__name__)


# ── Password ViewSet ──────────────────────────────────────────────────────────


@extend_schema_view(
    login=extend_schema(tags=["Password Auth"]),
    methods=extend_schema(tags=["Password Auth"]),
    change_direct=extend_schema(tags=["Password Auth"]),
    change_otp_request=extend_schema(tags=["Password Auth"]),
    change_otp_verify=extend_schema(tags=["Password Auth"]),
    reset_email_request=extend_schema(tags=["Password Auth"]),
    reset_email_verify=extend_schema(tags=["Password Auth"]),
    reset_phone_request=extend_schema(tags=["Password Auth"]),
    reset_phone_verify=extend_schema(tags=["Password Auth"]),
)
class PasswordViewSet(SerializerSeamsMixin, viewsets.GenericViewSet):
    permission_classes = [permissions.AllowAny]

    # Overridable serializer seams (see SerializerSeamsMixin).
    login_request_serializer_class = PasswordLoginSerializer
    change_direct_request_serializer_class = PasswordChangeDirectSerializer
    change_otp_request_serializer_class = PasswordOtpRequestSerializer
    change_otp_verify_request_serializer_class = PasswordOtpVerifySerializer
    reset_email_request_serializer_class = PasswordResetEmailRequestSerializer
    reset_email_verify_request_serializer_class = PasswordResetEmailVerifySerializer
    reset_phone_request_serializer_class = PasswordResetPhoneRequestSerializer
    reset_phone_verify_request_serializer_class = PasswordResetPhoneVerifySerializer
    register_request_serializer_class = PasswordRegisterSerializer
    auth_response_serializer_class = AuthResponseSerializer
    totp_challenge_response_serializer_class = TOTPChallengeResponseSerializer
    methods_response_serializer_class = PasswordMethodsResponseSerializer
    otp_sent_response_serializer_class = OtpSentResponseSerializer
    status_response_serializer_class = SimpleStatusSerializer

    _authenticated_actions = frozenset(
        {
            "methods",
            "change_direct",
            "change_otp_request",
            "change_otp_verify",
        }
    )

    def get_permissions(self):
        if self.action in self._authenticated_actions:
            return [permissions.IsAuthenticated()]
        return [permissions.AllowAny()]

    @extend_schema(
        description="Login with email/username and password. Returns `LoginResponse` — either `AuthResponse` (status=LOGGED_IN) or `TOTPChallengeResponse` (status=TOTP_REQUIRED). When TOTP is required, pass `challenge_token` to `POST /totp/challenge/verify/`.",
        request=PasswordLoginSerializer,
        responses={200: LoginResponseSerializer, 401: StapelErrorSerializer},
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="login",
        permission_classes=[permissions.AllowAny],
    )
    def login(self, request):
        from stapel_core.django.api.errors import error_403_forbidden

        from stapel_auth.conf import auth_settings

        if not auth_settings.AUTH_PASSWORD_LOGIN:
            return error_403_forbidden()

        from django.utils import timezone
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from stapel_auth.errors import ERR_423_ACCOUNT_LOCKED, retry_params
        from stapel_auth.services import AuditService, LockoutService, TOTPService

        serializer = self.get_login_request_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = serializer.validated_data["login"]

        is_locked, retry_after = LockoutService.check(identifier)
        if is_locked:
            return StapelErrorResponse(
                423, ERR_423_ACCOUNT_LOCKED, params=retry_params(retry_after)
            )

        user = PasswordService.login(identifier, serializer.validated_data["password"])
        if user is None:
            count = LockoutService.record_failure(identifier)
            duration = LockoutService.apply_lockout(identifier, count, request=request)
            if duration:
                return StapelErrorResponse(
                    423, ERR_423_ACCOUNT_LOCKED, params=retry_params(duration)
                )
            AuditService.log("login_failed", request=request, identifier=identifier)
            return StapelErrorResponse(401, ERR_401_INVALID_CREDENTIALS)
        if not user.is_active:
            AuditService.log(
                "login_failed", user=user, request=request, reason="account_disabled"
            )
            return StapelErrorResponse(401, ERR_401_ACCOUNT_DISABLED)

        LockoutService.clear(identifier)

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        # TOTP step-up on password login, gated by PASSWORD_LOGIN_STEP_UP
        # (default True — a password alone is phishable).
        if auth_settings.PASSWORD_LOGIN_STEP_UP and TOTPService.is_enabled(user):
            challenge_token = TOTPService.create_challenge(str(user.id))
            dto = TOTPChallengeResponse(
                status=TOTPChallengeStatus.TOTP_REQUIRED,
                challenge_token=challenge_token,
                expires_in=TOTPService.CHALLENGE_TTL,
            )
            return StapelResponse(
                self.get_totp_challenge_response_serializer_class()(dto)
            )

        access_token, refresh_token = _issue_session_tokens(user, request)
        dto = AuthResponse(
            status=AuthStatus.LOGGED_IN,
            user=user,
            tokens=TokenPairResponse(refresh=refresh_token, access=access_token),
        )
        response = Response(self.get_auth_response_serializer_class()(dto).data)
        set_jwt_cookies(response, access_token, refresh_token)
        return _add_login_hints(response, critical=True)

    @extend_schema(
        description="Return available methods for changing the account password.",
        responses={200: PasswordMethodsResponseSerializer},
    )
    @action(
        detail=False,
        methods=["get"],
        url_path="methods",
        permission_classes=[permissions.IsAuthenticated],
    )
    def methods(self, request):
        dto = PasswordMethodsResponse(
            has_password=request.user.has_usable_password(),
            methods=PasswordService.get_available_methods(request.user),
        )
        return StapelResponse(self.get_methods_response_serializer_class()(dto))

    @extend_schema(
        description="Change password by providing the current password.",
        request=PasswordChangeDirectSerializer,
        responses={200: None, 400: StapelErrorSerializer},
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="change",
        permission_classes=[permissions.IsAuthenticated],
    )
    def change_direct(self, request):
        if not request.user.has_usable_password():
            return StapelErrorResponse(400, ERR_400_NO_PASSWORD)
        serializer = self.get_change_direct_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        ok = PasswordService.change_via_old(
            request.user,
            serializer.validated_data["old_password"],
            serializer.validated_data["new_password"],
        )
        if not ok:
            return StapelErrorResponse(400, ERR_400_WRONG_PASSWORD)
        from stapel_auth.dto import SimpleStatusResponse

        return StapelResponse(
            self.get_status_response_serializer_class()(
                SimpleStatusResponse(status="password_changed")
            )
        )

    @extend_schema(
        description="Request OTP to own verified email or phone in order to change password.",
        request=PasswordOtpRequestSerializer,
        responses={
            200: OtpSentResponseSerializer,
            400: StapelErrorSerializer,
            422: StapelErrorSerializer,
            429: StapelErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="change/otp/request",
        permission_classes=[permissions.IsAuthenticated],
    )
    def change_otp_request(self, request):
        serializer = self.get_change_otp_request_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        masked = PasswordService.send_change_otp(
            request.user, serializer.validated_data["method"]
        )
        dto = OtpSentResponse(message="Verification code sent", target=masked)
        return StapelResponse(self.get_otp_sent_response_serializer_class()(dto))

    @extend_schema(
        description="Verify OTP and set new password (for authenticated users).",
        request=PasswordOtpVerifySerializer,
        responses={200: None, 400: StapelErrorSerializer},
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="change/otp/verify",
        permission_classes=[permissions.IsAuthenticated],
    )
    def change_otp_verify(self, request):
        serializer = self.get_change_otp_verify_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        PasswordService.change_via_otp(
            request.user,
            method=serializer.validated_data["method"],
            code=serializer.validated_data["code"],
            new_password=serializer.validated_data["new_password"],
        )
        from stapel_auth.dto import SimpleStatusResponse

        return StapelResponse(
            self.get_status_response_serializer_class()(
                SimpleStatusResponse(status="password_changed")
            )
        )

    @extend_schema(
        description="Request OTP to verified email to reset a forgotten password (unauthenticated).",
        request=PasswordResetEmailRequestSerializer,
        responses={
            200: OtpSentResponseSerializer,
            403: StapelErrorSerializer,
            404: StapelErrorSerializer,
            429: StapelErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="reset/email/request",
        permission_classes=[permissions.AllowAny],
    )
    def reset_email_request(self, request):
        serializer = self.get_reset_email_request_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        masked = PasswordService.reset_request(email=serializer.validated_data["email"])
        return StapelResponse(
            self.get_otp_sent_response_serializer_class()(
                OtpSentResponse(message="Verification code sent", target=masked)
            )
        )

    @extend_schema(
        description="Verify email OTP and set new password. Returns tokens — the user is logged in.",
        request=PasswordResetEmailVerifySerializer,
        responses={
            200: AuthResponseSerializer,
            400: StapelErrorSerializer,
            404: StapelErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="reset/email/verify",
        permission_classes=[permissions.AllowAny],
    )
    def reset_email_verify(self, request):
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from stapel_auth.staff_roles import create_tokens_for_user

        serializer = self.get_reset_email_verify_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        user = PasswordService.reset_verify(
            email=serializer.validated_data["email"],
            code=serializer.validated_data["code"],
            new_password=serializer.validated_data["new_password"],
        )
        access_token, refresh_token = create_tokens_for_user(user)
        dto = AuthResponse(
            status=AuthStatus.LOGGED_IN,
            user=user,
            tokens=TokenPairResponse(refresh=refresh_token, access=access_token),
        )
        response = Response(self.get_auth_response_serializer_class()(dto).data)
        set_jwt_cookies(response, access_token, refresh_token)
        return response

    @extend_schema(
        description="Request OTP to verified phone to reset a forgotten password (unauthenticated).",
        request=PasswordResetPhoneRequestSerializer,
        responses={
            200: OtpSentResponseSerializer,
            403: StapelErrorSerializer,
            404: StapelErrorSerializer,
            429: StapelErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="reset/phone/request",
        permission_classes=[permissions.AllowAny],
    )
    def reset_phone_request(self, request):
        serializer = self.get_reset_phone_request_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        masked = PasswordService.reset_request(phone=serializer.validated_data["phone"])
        return StapelResponse(
            self.get_otp_sent_response_serializer_class()(
                OtpSentResponse(message="Verification code sent", target=masked)
            )
        )

    @extend_schema(
        description="Verify phone OTP and set new password. Returns tokens — the user is logged in.",
        request=PasswordResetPhoneVerifySerializer,
        responses={
            200: AuthResponseSerializer,
            400: StapelErrorSerializer,
            404: StapelErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="reset/phone/verify",
        permission_classes=[permissions.AllowAny],
    )
    def reset_phone_verify(self, request):
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from stapel_auth.staff_roles import create_tokens_for_user

        serializer = self.get_reset_phone_verify_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        user = PasswordService.reset_verify(
            phone=serializer.validated_data["phone"],
            code=serializer.validated_data["code"],
            new_password=serializer.validated_data["new_password"],
        )
        access_token, refresh_token = create_tokens_for_user(user)
        dto = AuthResponse(
            status=AuthStatus.LOGGED_IN,
            user=user,
            tokens=TokenPairResponse(refresh=refresh_token, access=access_token),
        )
        response = Response(self.get_auth_response_serializer_class()(dto).data)
        set_jwt_cookies(response, access_token, refresh_token)
        return response

    @extend_schema(
        description="Register a new account with email/phone/username and password. Disabled by default — enable via AUTH_PASSWORD_REGISTRATION setting.",
        request=PasswordRegisterSerializer,
        responses={
            200: AuthResponseSerializer,
            400: StapelErrorSerializer,
            403: StapelErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="register",
        permission_classes=[permissions.AllowAny],
    )
    def register(self, request):
        from django.contrib.auth import get_user_model
        from django.contrib.auth.password_validation import validate_password
        from django.core.exceptions import ValidationError
        from stapel_core.django.api.errors import error_403_forbidden

        from stapel_auth.conf import auth_settings

        if not auth_settings.AUTH_PASSWORD_REGISTRATION:
            return error_403_forbidden()

        serializer = self.get_register_request_serializer_class()(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Validate password strength via Django validators
        try:
            validate_password(data["password"])
        except ValidationError:
            return StapelErrorResponse(400, ERR_400_BAD_REQUEST)

        User = get_user_model()

        # Check uniqueness
        email = data.get("email")
        phone = data.get("phone")
        username = data.get("username")

        if email and User.objects.filter(email=email).exists():
            return StapelErrorResponse(409, ERR_409_EMAIL_TAKEN)
        if phone and User.objects.filter(phone=phone).exists():
            return StapelErrorResponse(409, ERR_409_PHONE_TAKEN)
        if username and User.objects.filter(username=username).exists():
            return StapelErrorResponse(409, ERR_409_USERNAME_TAKEN)

        user = User.objects.create(
            email=email,
            phone=phone,
            username=username or (email.split("@")[0] if email else phone),
            is_email_verified=bool(email),
            is_phone_verified=bool(phone),
        )
        user.set_password(data["password"])
        user.save(update_fields=["password"])

        self._publish_user_registered(user, request=request)

        access_token, refresh_token = _issue_session_tokens(user, request)
        dto = AuthResponse(
            status=AuthStatus.REGISTERED,
            user=user,
            tokens=TokenPairResponse(refresh=refresh_token, access=access_token),
        )
        from stapel_core.django.jwt.utils import set_jwt_cookies

        response = StapelResponse(self.get_auth_response_serializer_class()(dto))
        set_jwt_cookies(response, access_token, refresh_token)
        return response

    def _publish_user_registered(self, user, request=None) -> None:
        from stapel_auth.otp.views import _notify_user_registered

        _notify_user_registered(user, request=request)
