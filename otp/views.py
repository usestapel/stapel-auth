"""OTP authentication views: email/phone OTP, OAuth callbacks, authenticator change."""

import logging

from django.conf import settings
from django.contrib.auth import get_user_model
from drf_spectacular.utils import (
    OpenApiExample,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from rest_framework import permissions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from stapel_core.django.errors import (
    ERR_400_BAD_REQUEST,
    ERR_401_UNAUTHORIZED,
    StapelErrorResponse,
    StapelResponse,
    error_429_rate_limit,
    error_500_internal,
)
from stapel_core.django.openapi import (
    StapelErrorSerializer,
)

from stapel_auth.errors import *
from stapel_auth.mfa.dto import TOTPChallengeResponse, TOTPChallengeStatus
from stapel_auth.mfa.serializers import (
    TOTPChallengeResponseSerializer,
)
from stapel_auth.models import LoginAttempt
from stapel_auth.oauth.serializers import OAuthSerializer
from stapel_auth.oauth.services import OAuthService
from stapel_auth.otp.dto import (
    DelayedCancelResponse,
    DelayedInitiateResponse,
    DelayedStatusResponse,
    InstantRequestNewResponse,
    InstantRequestOldResponse,
    InstantVerifyOldResponse,
    OtpSentResponse,
)
from stapel_auth.otp.serializers import (
    AnonymousAuthSerializer,
    DelayedCancelResponseSerializer,
    DelayedChangeCancelSerializer,
    DelayedChangeInitiateSerializer,
    DelayedInitiateResponseSerializer,
    DelayedStatusResponseSerializer,
    EmailAuthRequestSerializer,
    EmailAuthVerifySerializer,
    InstantChangeRequestNewSerializer,
    InstantChangeRequestOldSerializer,
    InstantChangeVerifyNewSerializer,
    InstantChangeVerifyOldSerializer,
    InstantRequestNewResponseSerializer,
    InstantRequestOldResponseSerializer,
    InstantVerifyOldResponseSerializer,
    OtpSentResponseSerializer,
    PhoneAuthRequestSerializer,
    PhoneAuthVerifySerializer,
)
from stapel_auth.otp.services import (
    AuthenticatorChangeService,
    EmailVerificationService,
    PhoneVerificationService,
)
from stapel_auth.sessions.dto import (
    AuthResponse,
    AuthStatus,
    LogoutResponse,
    TokenPairResponse,
    TokenVerifyResponse,
)
from stapel_auth.sessions.serializers import (
    AuthResponseSerializer,
    LoginResponseSerializer,
    LogoutResponseSerializer,
    TokenVerifyResponseSerializer,
    TokenVerifySerializer,
    UserSerializer,
)

logger = logging.getLogger(__name__)


class OAuthEmailNotVerified(Exception):
    """OAuth email matches an existing account but the provider did not
    verify it — auto-merge would be an account-takeover vector."""


def _sanitize_redirect_after(value: str) -> str:
    """Allow only same-site relative paths or URLs on the FRONTEND_URL origin.

    An unvalidated value here is an open redirect, and (worse) the OAuth
    callback used to append session tokens to it — full token exfiltration
    to an attacker-chosen host.
    """
    if not value:
        return ""
    if value.startswith("/") and not value.startswith("//") and not value.startswith("/\\"):
        return value
    from urllib.parse import urlparse

    from stapel_auth.conf import auth_settings

    frontend = getattr(auth_settings, "FRONTEND_URL", "") or ""
    if frontend:
        f, v = urlparse(frontend), urlparse(value)
        if v.scheme == f.scheme and v.netloc and v.netloc == f.netloc:
            return value
    logger.warning("Rejected oauth redirect_after target: %r", value)
    return ""


User = get_user_model()


def _notify_user_registered(user, request=None) -> None:
    """Fan out the registration milestone.

    1. stapel_core.signals.user_registered — in-process extension point.
    2. stapel_core.comm.emit("user.registered") — cross-module/cross-service
       action with the same payload the legacy bus publish carried.
    Failures are logged, never raised — registration must not fail because a
    listener/broker is down.
    """
    try:
        from stapel_core.signals import user_registered

        user_registered.send(sender=user.__class__, user=user, request=request)
    except Exception:
        logger.exception("user_registered signal failed for user %s", user.id)

    try:
        from django.db import transaction

        from stapel_core.comm import emit

        # Emit inside its OWN atomic block so this best-effort fan-out is
        # honest in BOTH request modes. Under ATOMIC_REQUESTS=True the caller
        # runs inside the request transaction; a failing emit there marks that
        # transaction rollback-only (comm/actions.py), so swallowing the
        # exception would NOT save registration — the next DB query raises
        # TransactionManagementError and the whole request (created user
        # included) rolls back with a 500. Wrapping emit in a nested atomic
        # isolates the failure to a savepoint: Django rolls that savepoint
        # back and clears needs_rollback, leaving the request transaction
        # healthy. In autocommit mode the block is the outermost atomic and
        # behaves identically. Being inside an atomic also silences the
        # emit-outside-atomic runtime guard's per-registration WARNING spam.
        with transaction.atomic():
            emit(  # emit-check: ok — best-effort fan-out wrapped in its own atomic; the user is already saved by the caller, this helper has no local ORM write, and the swallow + savepoint isolation mean a broker/outbox/schema failure never fails registration in either request mode
                "user.registered",
                {
                    "user_id": str(user.id),
                    "auth_type": user.auth_type or "unknown",
                    "email": user.email,
                },
                key=str(user.id),
                service="auth",
            )
    except Exception:
        logger.exception("Failed to emit user.registered for user %s", user.id)


# ── Sub-package cross-imports ─────────────────────────────────────────────────
from stapel_auth.sessions.views import (
    _CH_HINTS,
    _add_login_hints,
    _issue_session_tokens,
)
from stapel_auth.utils import SerializerSeamsMixin


@extend_schema_view(
    email_request=extend_schema(tags=["Email Auth"]),
    email_verify=extend_schema(tags=["Email Auth"]),
    phone_request=extend_schema(tags=["Phone Auth"]),
    phone_verify=extend_schema(tags=["Phone Auth"]),
    anonymous=extend_schema(tags=["Anonymous Auth"]),
    oauth_login=extend_schema(tags=["OAuth"]),
    oauth_authorize=extend_schema(tags=["OAuth"]),
    oauth_callback=extend_schema(tags=["OAuth"]),
    logout=extend_schema(tags=["Session"]),
    logout_get=extend_schema(tags=["Session"]),
    me=extend_schema(tags=["User"]),
    verify_token=extend_schema(tags=["Token"]),
)
class AuthViewSet(SerializerSeamsMixin, viewsets.GenericViewSet):
    """
    ViewSet for authentication operations
    """

    permission_classes = [permissions.AllowAny]

    # Overridable serializer seams (see SerializerSeamsMixin).
    email_request_serializer_class = EmailAuthRequestSerializer
    email_verify_request_serializer_class = EmailAuthVerifySerializer
    phone_request_serializer_class = PhoneAuthRequestSerializer
    phone_verify_request_serializer_class = PhoneAuthVerifySerializer
    anonymous_request_serializer_class = AnonymousAuthSerializer
    otp_sent_response_serializer_class = OtpSentResponseSerializer
    auth_response_serializer_class = AuthResponseSerializer
    totp_challenge_response_serializer_class = TOTPChallengeResponseSerializer
    logout_response_serializer_class = LogoutResponseSerializer
    me_response_serializer_class = UserSerializer
    token_verify_response_serializer_class = TokenVerifyResponseSerializer

    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.headers.get("x-forwarded-for")
        if x_forwarded_for:
            ip = x_forwarded_for.split(",")[0]
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip

    def set_auth_cookies(self, response, refresh_token):
        """Set JWT tokens as HTTP-only cookies"""
        from stapel_core.django.utils import set_jwt_cookies

        access_token = str(refresh_token.access_token)
        refresh_token_str = str(refresh_token)
        set_jwt_cookies(response, access_token, refresh_token_str)
        return response

    def log_login_attempt(self, identifier, attempt_type, request):
        """Log login attempt"""
        try:
            LoginAttempt.objects.create(
                identifier=identifier,
                attempt_type=attempt_type,
                ip_address=self.get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
            )
        except Exception as e:
            logger.error(f"Failed to log login attempt: {e}")

    @extend_schema(
        description="""Request email verification code (OTP).

**Notes:**
- OTP codes expire after 10 minutes
- Rate limited to 1 request per 30 seconds per email/device
- If authenticated non-anonymous user requests OTP for an email already registered to another account, returns 409 Conflict
- Admin accounts (staff/superuser) always receive real OTP even in mock mode for security
""",
        request=EmailAuthRequestSerializer,
        responses={
            200: OtpSentResponseSerializer,
            400: StapelErrorSerializer,
            409: StapelErrorSerializer,
            422: StapelErrorSerializer,
            500: StapelErrorSerializer,
        },
        examples=[
            OpenApiExample(
                "Email request",
                value={"email": "user@example.com", "device_id": "device-12345"},
                request_only=True,
            ),
            OpenApiExample(
                "Success response",
                value={
                    "message": "Verification code sent successfully",
                    "target": "user@example.com",
                },
                response_only=True,
                status_codes=["200"],
            ),
            OpenApiExample(
                "Rate limit error",
                value={
                    "localizable_error": "error.429.rate_limit",
                    "error": "Too many attempts. Try again in 1 minutes.",
                    "params": {
                        "retry_after": 30,
                        "retry_after_minutes": 1,
                        "retry_after_display": "0:30",
                    },
                },
                response_only=True,
                status_codes=["429"],
            ),
        ],
    )
    @action(detail=False, methods=["post"], url_path="email/request")
    def email_request(self, request):
        """Request email verification code"""
        from stapel_core.django.errors import error_403_forbidden

        from stapel_auth.conf import auth_settings

        if (
            not auth_settings.AUTH_EMAIL_LOGIN
            and not auth_settings.AUTH_EMAIL_REGISTRATION
        ):
            return error_403_forbidden()
        serializer = self.get_email_request_serializer_class()(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data["email"]
            device_id = serializer.validated_data.get("device_id")

            # Check if authenticated non-anonymous user is requesting OTP for existing email
            request_user = request.user if request.user.is_authenticated else None
            if request_user and not request_user.is_anonymous:
                # Non-anonymous user trying to add/change email
                existing_user = (
                    User.objects.filter(email=email).exclude(id=request_user.id).first()
                )
                if existing_user:
                    return StapelErrorResponse(409, ERR_409_EMAIL_TAKEN)

            # Check if email is reserved by a pending change request
            from stapel_auth.models import (
                AuthenticatorChangeRequest,
                AuthenticatorChangeStatus,
            )

            reserved = AuthenticatorChangeRequest.objects.filter(
                new_value=email,
                change_type="email",
                status=AuthenticatorChangeStatus.PENDING,
            ).exists()
            if reserved:
                return StapelErrorResponse(409, ERR_409_EMAIL_RESERVED)

            # Check if target email belongs to admin (staff/superuser) - force real OTP
            force_real_otp = False
            target_user = User.objects.filter(email=email).first()
            if target_user and (target_user.is_staff or target_user.is_superuser):
                force_real_otp = True
                logger.info(f"Admin account detected for {email}, forcing real OTP")

            # Store device_id in session if provided
            if device_id:
                request.session["device_id"] = device_id

            # Send verification code
            verification_service = EmailVerificationService()
            verification = verification_service.send_verification_code(
                email, device_id, force_real_otp=force_real_otp
            )

            # Handle different response types
            if isinstance(verification, dict):
                # Error responses from service
                if verification.get("error") == "rate_limit":
                    return error_429_rate_limit(verification.get("retry_after"))
                elif verification.get("error") == "blocked":
                    return StapelErrorResponse(
                        422,
                        ERR_422_BLOCKED,
                        params=retry_params(verification.get("retry_after")),
                    )
            elif verification:
                dto = OtpSentResponse(
                    message="Verification code sent successfully", target=email
                )
                return StapelResponse(
                    self.get_otp_sent_response_serializer_class()(dto),
                    status=status.HTTP_200_OK,
                )

            return StapelErrorResponse(500, ERR_500_SEND_FAILED)

    @extend_schema(
        description="""Verify email and authenticate/register.

**Authentication Flows:**
- **Unauthenticated user + new email** → REGISTERED (new account created)
- **Unauthenticated user + existing email** → LOGGED_IN (login to existing account)
- **Anonymous user + new email** → REGISTERED (anonymous completes registration)
- **Anonymous user + existing email** → MERGED (anonymous merged into existing account)
- **Authenticated user + own/new email** → MODIFIED (user adds/changes email)
- **Invalid/expired code** → REJECTED

**Status values:**
- `REJECTED` - Invalid code, expired code, or blocked
- `REGISTERED` - New account created or anonymous completed registration
- `LOGGED_IN` - Existing user logged in
- `MERGED` - Anonymous user merged into existing account
- `MODIFIED` - Authenticated user added/changed email
""",
        request=EmailAuthVerifySerializer,
        responses={
            200: AuthResponseSerializer,
            400: StapelErrorSerializer,
            409: StapelErrorSerializer,
            422: StapelErrorSerializer,
        },
        examples=[
            OpenApiExample(
                "Email verify request",
                value={"email": "user@example.com", "code": "123456"},
                request_only=True,
            ),
            OpenApiExample(
                "Success - new user registered",
                value={
                    "status": "REGISTERED",
                    "user": {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "email": "user@example.com",
                    },
                    "tokens": {"access": "eyJ...", "refresh": "eyJ..."},
                },
                response_only=True,
                status_codes=["200"],
            ),
            OpenApiExample(
                "Success - existing user logged in",
                value={
                    "status": "LOGGED_IN",
                    "user": {
                        "id": "550e8400-e29b-41d4-a716-446655440000",
                        "email": "user@example.com",
                    },
                    "tokens": {"access": "eyJ...", "refresh": "eyJ..."},
                },
                response_only=True,
                status_codes=["200"],
            ),
            OpenApiExample(
                "Invalid code error",
                value={
                    "localizable_error": "error.400.invalid_code_attempts",
                    "error": "Invalid verification code. 2 attempts remaining.",
                    "params": {"attempts_remaining": 2},
                },
                response_only=True,
                status_codes=["400"],
            ),
        ],
    )
    @action(detail=False, methods=["post"], url_path="email/verify")
    def email_verify(self, request):
        """
        Verify email and authenticate/register.

        Returns status:
        - REJECTED: Invalid or expired code
        - REGISTERED: New account created (or anonymous completed registration)
        - LOGGED_IN: Existing user logged in
        - MERGED: Anonymous user merged into existing account
        - MODIFIED: Authenticated user added/changed email
        """
        from stapel_auth.security.services import LockoutService

        serializer = self.get_email_verify_request_serializer_class()(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data["email"]
            code = serializer.validated_data["code"]

            # Progressive lockout across verification records (same pattern
            # as password login) — blocks unbounded OTP guessing via
            # re-requested codes.
            is_locked, retry_after = LockoutService.check(email)
            if is_locked:
                return StapelErrorResponse(
                    423, ERR_423_ACCOUNT_LOCKED, params=retry_params(retry_after)
                )

            # Verify code
            verification_service = EmailVerificationService()
            result = verification_service.verify_code(email, code)

            # Handle verification errors (REJECTED status)
            if isinstance(result, dict):
                if result.get("error") == "blocked":
                    return StapelErrorResponse(
                        422,
                        ERR_422_BLOCKED,
                        params=retry_params(result.get("retry_after")),
                    )
                elif result.get("error") in ("expired", "expired_retry_allowed"):
                    return StapelErrorResponse(400, ERR_400_CODE_EXPIRED)
                elif result.get("error") == "invalid_code":
                    attempts_remaining = result.get("attempts_remaining")
                    self.log_login_attempt(email, "failed", request)
                    count = LockoutService.record_failure(email)
                    duration = LockoutService.apply_lockout(email, count, request=request)
                    if duration:
                        return StapelErrorResponse(
                            423, ERR_423_ACCOUNT_LOCKED, params=retry_params(duration)
                        )
                    if attempts_remaining is not None:
                        return StapelErrorResponse(
                            400,
                            ERR_400_INVALID_CODE_ATTEMPTS,
                            params={"attempts_remaining": attempts_remaining},
                        )
                    return StapelErrorResponse(400, ERR_400_INVALID_CODE)
                elif not result.get("success"):
                    self.log_login_attempt(email, "failed", request)
                    count = LockoutService.record_failure(email)
                    duration = LockoutService.apply_lockout(email, count, request=request)
                    if duration:
                        return StapelErrorResponse(
                            423, ERR_423_ACCOUNT_LOCKED, params=retry_params(duration)
                        )
                    return StapelErrorResponse(400, ERR_400_INVALID_CODE)

            # Code verified successfully - determine auth status
            LockoutService.clear(email)
            request_user = request.user if request.user.is_authenticated else None
            existing_user = User.objects.filter(email=email).first()
            auth_status = None
            user = None

            if request_user and not request_user.is_anonymous:
                # CASE: Authenticated non-anonymous user adding/changing email
                if existing_user and existing_user.id != request_user.id:
                    # Email belongs to another account - should not happen (checked in request)
                    return StapelErrorResponse(409, ERR_409_EMAIL_TAKEN)

                # Update current user's email
                request_user.email = email
                request_user.is_email_verified = True
                request_user.save()
                user = request_user
                auth_status = AuthStatus.MODIFIED

            elif request_user and request_user.is_anonymous:
                # CASE: Anonymous user
                if existing_user:
                    # MERGED: Email already exists - merge anonymous into existing account
                    # Transfer any data from anonymous user if needed
                    old_anonymous_id = request_user.id
                    user = existing_user
                    user.is_email_verified = True
                    user.save()
                    # Delete anonymous user
                    User.objects.filter(id=old_anonymous_id).delete()
                    auth_status = AuthStatus.MERGED
                else:
                    # REGISTERED: Convert anonymous to registered user
                    request_user.email = email
                    request_user.is_email_verified = True
                    request_user.is_anonymous = False
                    request_user.auth_type = "email"
                    request_user.upgrade_username_from_anonymous()
                    request_user.save()
                    user = request_user
                    auth_status = AuthStatus.REGISTERED

            else:
                # CASE: Unauthenticated user
                if existing_user:
                    # LOGGED_IN: Existing account
                    user = existing_user
                    user.is_email_verified = True
                    user.save()
                    auth_status = AuthStatus.LOGGED_IN
                else:
                    # REGISTERED: New account
                    user = User.objects.create(
                        email=email, auth_type="email", is_email_verified=True
                    )
                    self._publish_user_registered(user, request=request)
                    auth_status = AuthStatus.REGISTERED

            self.log_login_attempt(email, "success", request)
            access_token, refresh_token = _issue_session_tokens(user, request)
            tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
            auth_dto = AuthResponse(status=auth_status, user=user, tokens=tokens_dto)
            response = Response(
                self.get_auth_response_serializer_class()(auth_dto).data,
                status=status.HTTP_200_OK,
            )
            from stapel_core.django.utils import set_jwt_cookies

            set_jwt_cookies(response, access_token, refresh_token)
            return _add_login_hints(response)

    @extend_schema(
        description="""Request phone verification code (SMS OTP).

**Notes:**
- OTP codes expire after 10 minutes
- Rate limited to 1 request per 30 seconds per phone/device
- If authenticated non-anonymous user requests OTP for a phone already registered to another account, returns 409 Conflict
- Admin accounts (staff/superuser) always receive real OTP even in mock mode for security
""",
        request=PhoneAuthRequestSerializer,
        responses={
            200: OtpSentResponseSerializer,
            400: StapelErrorSerializer,
            409: StapelErrorSerializer,
            422: StapelErrorSerializer,
            500: StapelErrorSerializer,
        },
        examples=[
            OpenApiExample(
                "Phone request",
                value={"phone": "+12345678900", "device_id": "device-12345"},
                request_only=True,
            ),
            OpenApiExample(
                "Success response",
                value={
                    "message": "Verification code sent successfully",
                    "target": "+12345678900",
                },
                response_only=True,
                status_codes=["200"],
            ),
        ],
    )
    @action(detail=False, methods=["post"], url_path="phone/request")
    def phone_request(self, request):
        """Request phone verification code (OTP)"""
        from stapel_core.django.errors import error_403_forbidden

        from stapel_auth.conf import auth_settings

        if (
            not auth_settings.AUTH_PHONE_LOGIN
            and not auth_settings.AUTH_PHONE_REGISTRATION
        ):
            return error_403_forbidden()
        serializer = self.get_phone_request_serializer_class()(data=request.data)
        if serializer.is_valid(raise_exception=True):
            phone = serializer.validated_data["phone"]
            device_id = serializer.validated_data.get("device_id")

            # Check if authenticated non-anonymous user is requesting OTP for existing phone
            request_user = request.user if request.user.is_authenticated else None
            if request_user and not request_user.is_anonymous:
                # Non-anonymous user trying to add/change phone
                existing_user = (
                    User.objects.filter(phone=phone).exclude(id=request_user.id).first()
                )
                if existing_user:
                    return StapelErrorResponse(409, ERR_409_PHONE_TAKEN)

            # Check if phone is reserved by a pending change request
            from stapel_auth.models import (
                AuthenticatorChangeRequest,
                AuthenticatorChangeStatus,
            )

            reserved = AuthenticatorChangeRequest.objects.filter(
                new_value=phone,
                change_type="phone",
                status=AuthenticatorChangeStatus.PENDING,
            ).exists()
            if reserved:
                return StapelErrorResponse(409, ERR_409_PHONE_RESERVED)

            # Check if target phone belongs to admin (staff/superuser) - force real OTP
            force_real_otp = False
            target_user = User.objects.filter(phone=phone).first()
            if target_user and (target_user.is_staff or target_user.is_superuser):
                force_real_otp = True
                logger.info(f"Admin account detected for {phone}, forcing real OTP")

            # Store device_id in session if provided
            if device_id:
                request.session["device_id"] = device_id

            # Send verification code
            verification_service = PhoneVerificationService()
            verification = verification_service.send_verification_code(
                phone, device_id, force_real_otp=force_real_otp
            )

            # Handle different response types
            if isinstance(verification, dict):
                # Error responses from service
                if verification.get("error") == "rate_limit":
                    return error_429_rate_limit(verification.get("retry_after"))
                elif verification.get("error") == "blocked":
                    return StapelErrorResponse(
                        422,
                        ERR_422_BLOCKED,
                        params=retry_params(verification.get("retry_after")),
                    )
            elif verification:
                dto = OtpSentResponse(
                    message="Verification code sent successfully", target=phone
                )
                return StapelResponse(
                    self.get_otp_sent_response_serializer_class()(dto),
                    status=status.HTTP_200_OK,
                )

            return StapelErrorResponse(500, ERR_500_SEND_FAILED)

    @extend_schema(
        description="""Verify phone number and authenticate/register.

**Authentication Flows:**
- **Unauthenticated user + new phone** → REGISTERED (new account created)
- **Unauthenticated user + existing phone** → LOGGED_IN (login to existing account)
- **Anonymous user + new phone** → REGISTERED (anonymous completes registration)
- **Anonymous user + existing phone** → MERGED (anonymous merged into existing account)
- **Authenticated user + own/new phone** → MODIFIED (user adds/changes phone)
- **Invalid/expired code** → REJECTED

**Status values:**
- `REJECTED` - Invalid code, expired code, or blocked
- `REGISTERED` - New account created or anonymous completed registration
- `LOGGED_IN` - Existing user logged in
- `MERGED` - Anonymous user merged into existing account
- `MODIFIED` - Authenticated user added/changed phone
""",
        request=PhoneAuthVerifySerializer,
        responses={
            200: AuthResponseSerializer,
            400: StapelErrorSerializer,
            409: StapelErrorSerializer,
            422: StapelErrorSerializer,
        },
        examples=[
            OpenApiExample(
                "Phone verify request",
                value={"phone": "+12345678900", "code": "1234"},
                request_only=True,
            ),
        ],
    )
    @action(detail=False, methods=["post"], url_path="phone/verify")
    def phone_verify(self, request):
        """
        Verify phone number and authenticate/register.

        Returns status:
        - REJECTED: Invalid or expired code
        - REGISTERED: New account created (or anonymous completed registration)
        - LOGGED_IN: Existing user logged in
        - MERGED: Anonymous user merged into existing account
        - MODIFIED: Authenticated user added/changed phone
        """
        from stapel_auth.security.services import LockoutService

        serializer = self.get_phone_verify_request_serializer_class()(data=request.data)
        if serializer.is_valid(raise_exception=True):
            phone = serializer.validated_data["phone"]
            code = serializer.validated_data["code"]

            # Progressive lockout across verification records (same pattern
            # as password login) — blocks unbounded OTP guessing via
            # re-requested codes.
            is_locked, retry_after = LockoutService.check(phone)
            if is_locked:
                return StapelErrorResponse(
                    423, ERR_423_ACCOUNT_LOCKED, params=retry_params(retry_after)
                )

            # Verify code
            verification_service = PhoneVerificationService()
            result = verification_service.verify_code(phone, code)

            # Handle verification errors (REJECTED status)
            if isinstance(result, dict):
                if result.get("error") == "blocked":
                    return StapelErrorResponse(
                        422,
                        ERR_422_BLOCKED,
                        params=retry_params(result.get("retry_after")),
                    )
                elif result.get("error") in ("expired", "expired_retry_allowed"):
                    return StapelErrorResponse(400, ERR_400_CODE_EXPIRED)
                elif result.get("error") == "invalid_code":
                    attempts_remaining = result.get("attempts_remaining")
                    self.log_login_attempt(phone, "failed", request)
                    count = LockoutService.record_failure(phone)
                    duration = LockoutService.apply_lockout(phone, count, request=request)
                    if duration:
                        return StapelErrorResponse(
                            423, ERR_423_ACCOUNT_LOCKED, params=retry_params(duration)
                        )
                    if attempts_remaining is not None:
                        return StapelErrorResponse(
                            400,
                            ERR_400_INVALID_CODE_ATTEMPTS,
                            params={"attempts_remaining": attempts_remaining},
                        )
                    return StapelErrorResponse(400, ERR_400_INVALID_CODE)
                elif not result.get("success"):
                    self.log_login_attempt(phone, "failed", request)
                    count = LockoutService.record_failure(phone)
                    duration = LockoutService.apply_lockout(phone, count, request=request)
                    if duration:
                        return StapelErrorResponse(
                            423, ERR_423_ACCOUNT_LOCKED, params=retry_params(duration)
                        )
                    return StapelErrorResponse(400, ERR_400_INVALID_CODE)

            # Code verified successfully - determine auth status
            LockoutService.clear(phone)
            request_user = request.user if request.user.is_authenticated else None
            existing_user = User.objects.filter(phone=phone).first()
            auth_status = None
            user = None

            if request_user and not request_user.is_anonymous:
                # CASE: Authenticated non-anonymous user adding/changing phone
                if existing_user and existing_user.id != request_user.id:
                    # Phone belongs to another account - should not happen (checked in request)
                    return StapelErrorResponse(409, ERR_409_PHONE_TAKEN)

                # Update current user's phone
                request_user.phone = phone
                request_user.is_phone_verified = True
                request_user.save()
                user = request_user
                auth_status = AuthStatus.MODIFIED

            elif request_user and request_user.is_anonymous:
                # CASE: Anonymous user
                if existing_user:
                    # MERGED: Phone already exists - merge anonymous into existing account
                    # Transfer any data from anonymous user if needed
                    old_anonymous_id = request_user.id
                    user = existing_user
                    user.is_phone_verified = True
                    user.save()
                    # Delete anonymous user
                    User.objects.filter(id=old_anonymous_id).delete()
                    auth_status = AuthStatus.MERGED
                else:
                    # REGISTERED: Convert anonymous to registered user
                    request_user.phone = phone
                    request_user.is_phone_verified = True
                    request_user.is_anonymous = False
                    request_user.auth_type = "phone"
                    request_user.upgrade_username_from_anonymous()
                    request_user.save()
                    user = request_user
                    auth_status = AuthStatus.REGISTERED

            else:
                # CASE: Unauthenticated user
                if existing_user:
                    # LOGGED_IN: Existing account
                    user = existing_user
                    user.is_phone_verified = True
                    user.save()
                    auth_status = AuthStatus.LOGGED_IN
                else:
                    # REGISTERED: New account
                    user = User.objects.create(
                        phone=phone, auth_type="phone", is_phone_verified=True
                    )
                    auth_status = AuthStatus.REGISTERED

            self.log_login_attempt(phone, "success", request)
            access_token, refresh_token = _issue_session_tokens(user, request)
            tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
            auth_dto = AuthResponse(status=auth_status, user=user, tokens=tokens_dto)
            response = Response(
                self.get_auth_response_serializer_class()(auth_dto).data,
                status=status.HTTP_200_OK,
            )
            from stapel_core.django.utils import set_jwt_cookies

            set_jwt_cookies(response, access_token, refresh_token)
            return _add_login_hints(response)

    @extend_schema(
        description="Create anonymous user",
        request=AnonymousAuthSerializer,
        responses={201: AuthResponseSerializer, 400: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"])
    def anonymous(self, request):
        """Create anonymous user (or return existing anonymous session)."""
        serializer = self.get_anonymous_request_serializer_class()(data=request.data)
        if serializer.is_valid(raise_exception=True):
            # If caller already has a valid anonymous session, reuse it
            if (
                request.user
                and request.user.is_authenticated
                and request.user.is_anonymous
            ):
                user = request.user
            else:
                # Dedup by device_id: reuse recent anonymous user for same device
                device_id = serializer.validated_data.get("device_id")
                user = None
                if device_id:
                    from django.core.cache import cache

                    cache_key = f"anon_device:{device_id}"
                    existing_user_id = cache.get(cache_key)
                    if existing_user_id:
                        try:
                            existing = User.objects.get(
                                pk=existing_user_id, is_anonymous=True
                            )
                            user = existing
                        except User.DoesNotExist:
                            pass
                if user is None:
                    user = User.create_anonymous_user()
                if device_id:
                    from django.core.cache import cache

                    cache.set(f"anon_device:{device_id}", str(user.id), timeout=60)

            self.log_login_attempt(str(user.id), "success", request)
            access_token, refresh_token = _issue_session_tokens(user, request)
            tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
            auth_dto = AuthResponse(
                status=AuthStatus.REGISTERED, user=user, tokens=tokens_dto
            )
            response = Response(
                self.get_auth_response_serializer_class()(auth_dto).data,
                status=status.HTTP_201_CREATED,
            )
            from stapel_core.django.utils import set_jwt_cookies

            set_jwt_cookies(response, access_token, refresh_token)
            return response

    @extend_schema(
        description="OAuth authentication (Google, Facebook, etc.). Returns `LoginResponse` — normally `AuthResponse` (status=LOGGED_IN); with the `OAUTH_STEP_UP` setting enabled and TOTP enrolled, `TOTPChallengeResponse` (status=TOTP_REQUIRED) — pass `challenge_token` to `POST /totp/challenge/verify/`.",
        request=OAuthSerializer,
        responses={200: LoginResponseSerializer, 400: StapelErrorSerializer},
        examples=[
            OpenApiExample(
                "OAuth login request",
                value={"provider": "google", "access_token": "ya29.xxx"},
                request_only=True,
            ),
        ],
    )
    @action(detail=False, methods=["post"])
    def oauth_login(self, request):
        """OAuth authentication"""
        from stapel_core.django.errors import error_403_forbidden

        from stapel_auth.conf import auth_settings

        if (
            not auth_settings.AUTH_OAUTH_LOGIN
            and not auth_settings.AUTH_OAUTH_REGISTRATION
        ):
            return error_403_forbidden()
        provider = request.data.get("provider")
        access_token = request.data.get("access_token")

        if not provider or not access_token:
            return StapelErrorResponse(400, ERR_400_OAUTH_FIELDS_REQUIRED)

        ocore = OAuthService()
        user_data = ocore.get_user_data(provider, access_token)

        if not user_data:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)

        try:
            user = self._resolve_oauth_user(provider, user_data)
        except OAuthEmailNotVerified:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)
        self.log_login_attempt(str(user.id), "success", request)

        # No forced TOTP: the OAuth provider already authenticated the user.
        # Hosts that still want a second factor here opt in via OAUTH_STEP_UP.
        if auth_settings.OAUTH_STEP_UP:
            from stapel_auth.mfa.services import TOTPService

            if TOTPService.is_enabled(user):
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
        tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
        auth_dto = AuthResponse(
            status=AuthStatus.LOGGED_IN, user=user, tokens=tokens_dto
        )
        response = Response(
            self.get_auth_response_serializer_class()(auth_dto).data,
            status=status.HTTP_200_OK,
        )
        from stapel_core.django.utils import set_jwt_cookies

        set_jwt_cookies(response, access_token, refresh_token)
        return _add_login_hints(response)

    @extend_schema(
        description="Redirect browser to OAuth provider authorization page",
        responses={302: None},
    )
    @action(
        detail=False, methods=["get"], url_path="oauth/(?P<provider>[^/.]+)/authorize"
    )
    def oauth_authorize(self, request, provider=None):
        """Initiate server-side OAuth flow"""
        import secrets

        from django.core.cache import cache
        from django.shortcuts import redirect
        from stapel_core.django.errors import error_403_forbidden

        from stapel_auth.conf import auth_settings
        from stapel_auth.oauth_providers import PROVIDER_REGISTRY

        if (
            not auth_settings.AUTH_OAUTH_LOGIN
            and not auth_settings.AUTH_OAUTH_REGISTRATION
        ):
            return error_403_forbidden()

        p = PROVIDER_REGISTRY.get(provider)
        if not p:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)

        configs = auth_settings.OAUTH_PROVIDERS
        cfg = configs.get(provider)
        if not cfg or not cfg.client_id:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)

        state = secrets.token_urlsafe(32)
        redirect_uri = self._build_callback_uri(request, provider)

        cache.set(
            f"oauth_state:{state}",
            {
                "provider": provider,
                "redirect_uri": redirect_uri,
                "redirect_after": request.query_params.get("redirect_uri", ""),
            },
            timeout=600,
        )

        return redirect(p.get_authorization_url(cfg.client_id, redirect_uri, state))

    @extend_schema(
        description="OAuth provider callback — exchanges code for JWT and redirects to frontend",
        responses={302: None, 400: StapelErrorSerializer},
    )
    @action(
        detail=False, methods=["get"], url_path="oauth/(?P<provider>[^/.]+)/callback"
    )
    def oauth_callback(self, request, provider=None):
        """Handle OAuth authorization code callback"""
        from urllib.parse import urlencode

        from django.core.cache import cache
        from django.shortcuts import redirect

        from stapel_auth.conf import auth_settings
        from stapel_auth.oauth_providers import PROVIDER_REGISTRY

        error = request.query_params.get("error")
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if error or not code or not state:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)

        state_data = cache.get(f"oauth_state:{state}")
        if not state_data or state_data.get("provider") != provider:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)
        cache.delete(f"oauth_state:{state}")

        p = PROVIDER_REGISTRY.get(provider)
        if not p:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)

        configs = auth_settings.OAUTH_PROVIDERS
        cfg = configs.get(provider)
        if not cfg or not cfg.client_id:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)

        redirect_uri = state_data["redirect_uri"]
        access_token = p.exchange_code(
            cfg.client_id, cfg.client_secret, code, redirect_uri
        )
        if not access_token:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)

        ocore = OAuthService()
        user_data = ocore.get_user_data(provider, access_token)
        if not user_data:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)

        try:
            user = self._resolve_oauth_user(provider, user_data)
        except OAuthEmailNotVerified:
            return StapelErrorResponse(400, ERR_400_OAUTH_FAILED)
        self.log_login_attempt(str(user.id), "success", request)

        # No forced TOTP: the OAuth provider already authenticated the user.
        # Hosts that still want a second factor here opt in via OAUTH_STEP_UP.
        if auth_settings.OAUTH_STEP_UP:
            from stapel_auth.mfa.services import TOTPService

            if TOTPService.is_enabled(user):
                challenge_token = TOTPService.create_challenge(str(user.id))
                redirect_after = _sanitize_redirect_after(state_data.get("redirect_after", ""))
                # Encode redirect_after inside the TOTP challenge URL so the
                # frontend can resume the OAuth redirect flow after TOTP verify.
                params = {"token": challenge_token}
                if redirect_after:
                    params["redirect_after"] = redirect_after
                return redirect("/totp-challenge?" + urlencode(params))

        access_token, refresh_token = _issue_session_tokens(user, request)

        redirect_after = _sanitize_redirect_after(state_data.get("redirect_after", ""))
        if redirect_after:
            # Tokens travel as httponly cookies, never in the URL — query
            # strings end up in proxy logs, browser history and referrers.
            from stapel_core.django.utils import set_jwt_cookies

            response = redirect(redirect_after)
            set_jwt_cookies(response, access_token, refresh_token)
            return response

        tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
        auth_dto = AuthResponse(
            status=AuthStatus.LOGGED_IN, user=user, tokens=tokens_dto
        )
        response = Response(
            self.get_auth_response_serializer_class()(auth_dto).data,
            status=status.HTTP_200_OK,
        )
        from stapel_core.django.utils import set_jwt_cookies

        set_jwt_cookies(response, access_token, refresh_token)
        return response

    def _resolve_oauth_user(self, provider, user_data):
        """Find or create a user for an OAuth login, merging by email when possible.

        Priority:
        1. Exact match by (oauth_provider, oauth_id) — returning user.
        2. Existing account with the same verified email — authenticate as that
           user without overwriting their auth_type or existing OAuth link.
        3. Create a fresh user.
        """
        oauth_id = str(user_data.id)
        email = user_data.email

        # 1. Exact provider match
        try:
            return User.objects.get(oauth_provider=provider, oauth_id=oauth_id)
        except User.DoesNotExist:
            pass

        # 2. Same email → merge into existing account, but ONLY when the
        # provider asserts the email is verified. Merging on an unverified
        # address lets an attacker set a victim's email on their own OAuth
        # account and log in as the victim.
        email_verified = bool(getattr(user_data, "email_verified", False))
        if email:
            existing = User.objects.filter(email=email).first()
            if existing is not None:
                if email_verified:
                    return existing
                # Unverified email matching an existing account: neither
                # merge nor duplicate — the user must sign in with the
                # account's original method.
                raise OAuthEmailNotVerified(email)

        # 3. Brand-new user
        user = User.objects.create(
            email=email,
            oauth_provider=provider,
            oauth_id=oauth_id,
            auth_type="oauth",
            avatar=user_data.avatar,
            is_email_verified=email_verified,
        )
        self._publish_user_registered(user)
        return user

    def _publish_user_registered(self, user, request=None) -> None:
        _notify_user_registered(user, request=request)

    def _build_callback_uri(self, request, provider):
        """Build the OAuth callback URI using configured host or request."""
        base = getattr(settings, "OAUTH_CALLBACK_BASE_URL", "").rstrip("/")
        url_prefix = getattr(settings, "URL_PREFIX", "")
        path = f"/{url_prefix}api/oauth/{provider}/callback"
        if base:
            return base + path
        return request.build_absolute_uri(path)

    @extend_schema(
        description="Logout user and blacklist both access and refresh tokens",
        request=inline_serializer(
            name="LogoutRequest",
            fields={
                "refresh_token": serializers.CharField(
                    required=False,
                    help_text="Refresh token to blacklist (optional, will also use cookie if available)",
                ),
            },
        ),
        responses={200: LogoutResponseSerializer, 400: StapelErrorSerializer},
    )
    @action(
        detail=False, methods=["post"], permission_classes=[permissions.IsAuthenticated]
    )
    def logout(self, request):
        """POST endpoint to logout user"""
        return self._logout(request)

    @extend_schema(
        description="Logout user via GET request (for cookie-based authentication). Blacklists both access and refresh tokens.",
        responses={200: LogoutResponseSerializer, 400: StapelErrorSerializer},
    )
    @action(
        detail=False, methods=["get"], permission_classes=[permissions.IsAuthenticated]
    )
    def logout_get(self, request):
        """GET endpoint to logout user (for cookie-based authentication)"""
        return self._logout(request)

    def _logout(self, request):
        """Internal method to handle logout and blacklist tokens"""
        try:
            from datetime import datetime
            from datetime import timezone as dt_timezone

            from stapel_core.core.jwt_handler import JWTHandler
            from stapel_core.core.token_blacklist import TokenBlacklist
            from stapel_core.django.utils import (
                extract_jwt_from_request,
                load_jwt_config_from_settings,
            )

            # Extract tokens from cookies/headers
            access_token, refresh_token_cookie = extract_jwt_from_request(request)

            # Also check request body for refresh token (POST only)
            refresh_token_body = None
            if request.method == "POST":
                refresh_token_body = request.data.get("refresh_token")

            # Use cookie refresh token if body not provided
            refresh_token = refresh_token_body or refresh_token_cookie

            blacklist = TokenBlacklist()

            config = load_jwt_config_from_settings()
            jwt_handler = JWTHandler(config)

            # Blacklist access token
            if access_token:
                try:
                    payload = jwt_handler.decode_token(access_token, verify=False)
                    if payload and "jti" in payload:
                        jti = payload["jti"]
                        exp = payload.get("exp")
                        logger.info(f"Access token JTI: {jti[:8]}..., exp: {exp}")
                        if exp:
                            expires_in = datetime.fromtimestamp(
                                exp, tz=dt_timezone.utc
                            ) - datetime.now(dt_timezone.utc)
                            if expires_in.total_seconds() > 0:
                                success = blacklist.blacklist_token(jti, expires_in)
                                logger.info(
                                    f"Blacklisted access token {jti[:8]}...: {success}"
                                )
                            else:
                                logger.warning(
                                    "Access token already expired, not blacklisting"
                                )
                except Exception as e:
                    logger.warning(f"Failed to blacklist access token: {e}")

            # Blacklist refresh token and revoke session
            if refresh_token:
                try:
                    payload = jwt_handler.decode_token(refresh_token, verify=False)
                    if payload and "jti" in payload:
                        jti = payload["jti"]
                        exp = payload.get("exp")
                        logger.info(f"Refresh token JTI: {jti[:8]}..., exp: {exp}")
                        if exp:
                            expires_in = datetime.fromtimestamp(
                                exp, tz=dt_timezone.utc
                            ) - datetime.now(dt_timezone.utc)
                            if expires_in.total_seconds() > 0:
                                success = blacklist.blacklist_token(jti, expires_in)
                                logger.info(
                                    f"Blacklisted refresh token {jti[:8]}...: {success}"
                                )
                            else:
                                logger.warning(
                                    "Refresh token already expired, not blacklisting"
                                )
                        # Revoke session in DB so it disappears from active list immediately
                        from .services import SessionService as _SS

                        _SS.revoke_by_jti(jti)
                except Exception as e:
                    logger.warning(f"Failed to blacklist refresh token: {e}")

            # Create response
            dto = LogoutResponse(message="Successfully logged out")
            response = Response(
                self.get_logout_response_serializer_class()(dto).data,
                status=status.HTTP_200_OK,
            )

            # Clear JWT cookies
            cookie_name = getattr(settings, "JWT_COOKIE_NAME", "stapel_jwt")
            refresh_cookie_name = getattr(
                settings, "JWT_REFRESH_COOKIE_NAME", "stapel_refresh_jwt"
            )
            cookie_domain = getattr(settings, "JWT_COOKIE_DOMAIN", None)

            response.delete_cookie(cookie_name, path="/", domain=cookie_domain)
            response.delete_cookie(refresh_cookie_name, path="/", domain=cookie_domain)

            return response
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return error_500_internal()

    @extend_schema(
        description="Get current authenticated user information",
        responses={200: UserSerializer, 401: StapelErrorSerializer},
    )
    @action(
        detail=False, methods=["get"], permission_classes=[permissions.IsAuthenticated]
    )
    def me(self, request):
        """Get current user information"""
        # Check if user is actually authenticated
        if not request.user or not request.user.is_authenticated:
            # Log detailed info about failed authentication
            auth_header = request.headers.get("authorization", "")
            user_agent = request.headers.get("user-agent", "unknown")
            client_ip = request.headers.get(
                "x-forwarded-for", request.META.get("REMOTE_ADDR", "unknown")
            )

            # Check cookies
            _cookie_name = getattr(settings, "JWT_COOKIE_NAME", "stapel_jwt")
            _refresh_cookie_name = getattr(settings, "JWT_REFRESH_COOKIE_NAME", "stapel_refresh_jwt")
            jwt_cookie = request.COOKIES.get(_cookie_name, "")
            refresh_cookie = request.COOKIES.get(_refresh_cookie_name, "")

            # Log token info (last 10 chars for debugging without exposing full token)
            token_suffix = "no_token"
            if auth_header:
                token_suffix = f"header:{auth_header[-10:]}"
            elif jwt_cookie:
                token_suffix = f"cookie:{jwt_cookie[-10:]}"

            logger.warning(
                f"401 Unauthorized /api/me/ - "
                f"user={getattr(request.user, 'id', 'AnonymousUser')}, "
                f"token_suffix={token_suffix}, "
                f"auth_header_present={bool(auth_header)}, "
                f"jwt_cookie_present={bool(jwt_cookie)}, "
                f"refresh_cookie_present={bool(refresh_cookie)}, "
                f"user_agent={user_agent}, "
                f"client_ip={client_ip}"
            )

            resp = StapelErrorResponse(401, ERR_401_UNAUTHORIZED)
            resp["Accept-CH"] = _CH_HINTS
            return resp

        serializer = self.get_me_response_serializer_class()(request.user)
        resp = StapelResponse(serializer)
        resp["Accept-CH"] = _CH_HINTS
        return resp

    @extend_schema(
        description="Verify JWT token",
        request=TokenVerifySerializer,
        responses={200: TokenVerifyResponseSerializer, 401: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"])
    def verify_token(self, request):
        """Verify JWT token"""
        from stapel_core.django.jwt_provider import jwt_provider

        token = request.data.get("token")
        if not token:
            return StapelErrorResponse(400, ERR_400_TOKEN_REQUIRED)

        try:
            # Validate token using jwt_provider
            payload = jwt_provider.validate_token(token)

            if not payload:
                return StapelErrorResponse(401, ERR_401_TOKEN_INVALID)

            # Check if blacklisted
            if jwt_provider.is_blacklisted(token):
                return StapelErrorResponse(401, ERR_401_TOKEN_REVOKED)

            user_id = payload.get("user_id")
            user = User.objects.get(id=user_id)

            verify_dto = TokenVerifyResponse(valid=True, user=user)
            return StapelResponse(
                self.get_token_verify_response_serializer_class()(verify_dto),
                status=status.HTTP_200_OK,
            )
        except User.DoesNotExist:
            return StapelErrorResponse(401, ERR_401_USER_NOT_FOUND)
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return StapelErrorResponse(401, ERR_401_TOKEN_INVALID)


@extend_schema_view(
    phone_instant_request_old=extend_schema(tags=["Phone Change"]),
    phone_instant_verify_old=extend_schema(tags=["Phone Change"]),
    phone_instant_request_new=extend_schema(tags=["Phone Change"]),
    phone_instant_verify_new=extend_schema(tags=["Phone Change"]),
    phone_delayed_initiate=extend_schema(tags=["Phone Change"]),
    phone_delayed_status=extend_schema(tags=["Phone Change"]),
    phone_delayed_cancel=extend_schema(tags=["Phone Change"]),
    email_instant_request_old=extend_schema(tags=["Email Change"]),
    email_instant_verify_old=extend_schema(tags=["Email Change"]),
    email_instant_request_new=extend_schema(tags=["Email Change"]),
    email_instant_verify_new=extend_schema(tags=["Email Change"]),
    email_delayed_initiate=extend_schema(tags=["Email Change"]),
    email_delayed_status=extend_schema(tags=["Email Change"]),
    email_delayed_cancel=extend_schema(tags=["Email Change"]),
)
class AuthenticatorChangeViewSet(SerializerSeamsMixin, viewsets.GenericViewSet):
    """ViewSet for authenticator (phone/email) change flows."""

    permission_classes = [permissions.IsAuthenticated]

    # Overridable serializer seams (see SerializerSeamsMixin); the same
    # serializers back both the phone and the email flavours of each flow.
    instant_request_old_request_serializer_class = InstantChangeRequestOldSerializer
    instant_verify_old_request_serializer_class = InstantChangeVerifyOldSerializer
    instant_request_new_request_serializer_class = InstantChangeRequestNewSerializer
    instant_verify_new_request_serializer_class = InstantChangeVerifyNewSerializer
    delayed_initiate_request_serializer_class = DelayedChangeInitiateSerializer
    delayed_cancel_request_serializer_class = DelayedChangeCancelSerializer
    instant_request_old_response_serializer_class = InstantRequestOldResponseSerializer
    instant_verify_old_response_serializer_class = InstantVerifyOldResponseSerializer
    instant_request_new_response_serializer_class = InstantRequestNewResponseSerializer
    auth_response_serializer_class = AuthResponseSerializer
    delayed_initiate_response_serializer_class = DelayedInitiateResponseSerializer
    delayed_status_response_serializer_class = DelayedStatusResponseSerializer
    delayed_cancel_response_serializer_class = DelayedCancelResponseSerializer

    def _service_error_to_response(self, result):
        """Convert service error dict to StapelErrorResponse."""
        error = result.get("error", "unknown_error")

        if error == "rate_limit":
            return error_429_rate_limit(result.get("retry_after"))
        if error == "blocked":
            return StapelErrorResponse(
                422,
                ERR_422_BLOCKED,
                params=retry_params(result.get("retry_after")),
            )
        if error == "not_available":
            return StapelErrorResponse(409, ERR_400_NOT_AVAILABLE)
        if error == "no_current_value":
            return StapelErrorResponse(400, ERR_400_NO_CURRENT_VALUE)
        if error in ("invalid_change_token", "value_mismatch"):
            return StapelErrorResponse(400, ERR_400_INVALID_CHANGE_TOKEN)
        if error == "not_found":
            return StapelErrorResponse(404, ERR_404_CHANGE_NOT_FOUND)
        if error == "invalid_code":
            return StapelErrorResponse(
                400,
                ERR_400_INVALID_CODE,
                params={"attempts_remaining": result.get("attempts_remaining")},
            )
        if error in ("expired", "expired_retry_allowed"):
            return StapelErrorResponse(400, ERR_400_CODE_EXPIRED)
        if error == "send_failed":
            return StapelErrorResponse(500, ERR_500_SEND_FAILED)

        return StapelErrorResponse(400, ERR_400_BAD_REQUEST)

    # ── Phone Instant ────────────────────────────────────────

    @extend_schema(
        request=InstantChangeRequestOldSerializer,
        responses={200: InstantRequestOldResponseSerializer},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/instant/request-old")
    def phone_instant_request_old(self, request):
        serializer = self.get_instant_request_old_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        svc = AuthenticatorChangeService()
        result = svc.request_old_otp(
            request.user, "phone", serializer.validated_data.get("device_id")
        )
        if result.get("success"):
            dto = InstantRequestOldResponse(
                message="Verification code sent to your current phone",
                masked_target=result["masked_target"],
            )
            return StapelResponse(
                self.get_instant_request_old_response_serializer_class()(dto)
            )
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeVerifyOldSerializer,
        responses={200: InstantVerifyOldResponseSerializer},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/instant/verify-old")
    def phone_instant_verify_old(self, request):
        serializer = self.get_instant_verify_old_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        svc = AuthenticatorChangeService()
        result = svc.verify_old_otp(
            request.user, "phone", serializer.validated_data["code"]
        )
        if result.get("success"):
            dto = InstantVerifyOldResponse(
                status="OLD_VERIFIED",
                change_token=result["change_token"],
                expires_at=result["expires_at"],
            )
            return StapelResponse(
                self.get_instant_verify_old_response_serializer_class()(dto)
            )
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeRequestNewSerializer,
        responses={
            200: InstantRequestNewResponseSerializer,
            409: StapelErrorSerializer,
        },
    )
    @action(detail=False, methods=["post"], url_path="phone/change/instant/request-new")
    def phone_instant_request_new(self, request):
        serializer = self.get_instant_request_new_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("phone")
        if not new_value:
            return StapelErrorResponse(400, ERR_400_PHONE_REQUIRED)
        svc = AuthenticatorChangeService()
        result = svc.request_new_otp(
            request.user, "phone", new_value, serializer.validated_data["change_token"]
        )
        if result.get("success"):
            dto = InstantRequestNewResponse(
                message="Verification code sent to new phone"
            )
            return StapelResponse(
                self.get_instant_request_new_response_serializer_class()(dto)
            )
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeVerifyNewSerializer,
        responses={200: AuthResponseSerializer, 409: None},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/instant/verify-new")
    def phone_instant_verify_new(self, request):
        serializer = self.get_instant_verify_new_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("phone")
        if not new_value:
            return StapelErrorResponse(400, ERR_400_PHONE_REQUIRED)
        svc = AuthenticatorChangeService()
        result = svc.verify_new_and_apply(
            request.user,
            "phone",
            new_value,
            serializer.validated_data["code"],
            serializer.validated_data["change_token"],
        )
        if result.get("success"):
            request.user.refresh_from_db()
            access_token, refresh_token = _issue_session_tokens(request.user, request)
            tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
            auth_dto = AuthResponse(
                status=AuthStatus.MODIFIED, user=request.user, tokens=tokens_dto
            )
            response = Response(
                self.get_auth_response_serializer_class()(auth_dto).data
            )
            from stapel_core.django.utils import set_jwt_cookies

            set_jwt_cookies(response, access_token, refresh_token)
            return response
        return self._service_error_to_response(result)

    # ── Email Instant ────────────────────────────────────────

    @extend_schema(
        request=InstantChangeRequestOldSerializer,
        responses={200: InstantRequestOldResponseSerializer},
    )
    @action(detail=False, methods=["post"], url_path="email/change/instant/request-old")
    def email_instant_request_old(self, request):
        serializer = self.get_instant_request_old_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        svc = AuthenticatorChangeService()
        result = svc.request_old_otp(
            request.user, "email", serializer.validated_data.get("device_id")
        )
        if result.get("success"):
            dto = InstantRequestOldResponse(
                message="Verification code sent to your current email",
                masked_target=result["masked_target"],
            )
            return StapelResponse(
                self.get_instant_request_old_response_serializer_class()(dto)
            )
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeVerifyOldSerializer,
        responses={200: InstantVerifyOldResponseSerializer},
    )
    @action(detail=False, methods=["post"], url_path="email/change/instant/verify-old")
    def email_instant_verify_old(self, request):
        serializer = self.get_instant_verify_old_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        svc = AuthenticatorChangeService()
        result = svc.verify_old_otp(
            request.user, "email", serializer.validated_data["code"]
        )
        if result.get("success"):
            dto = InstantVerifyOldResponse(
                status="OLD_VERIFIED",
                change_token=result["change_token"],
                expires_at=result["expires_at"],
            )
            return StapelResponse(
                self.get_instant_verify_old_response_serializer_class()(dto)
            )
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeRequestNewSerializer,
        responses={
            200: InstantRequestNewResponseSerializer,
            409: StapelErrorSerializer,
        },
    )
    @action(detail=False, methods=["post"], url_path="email/change/instant/request-new")
    def email_instant_request_new(self, request):
        serializer = self.get_instant_request_new_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("email")
        if not new_value:
            return StapelErrorResponse(400, ERR_400_EMAIL_REQUIRED)
        svc = AuthenticatorChangeService()
        result = svc.request_new_otp(
            request.user, "email", new_value, serializer.validated_data["change_token"]
        )
        if result.get("success"):
            dto = InstantRequestNewResponse(
                message="Verification code sent to new email"
            )
            return StapelResponse(
                self.get_instant_request_new_response_serializer_class()(dto)
            )
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeVerifyNewSerializer,
        responses={200: AuthResponseSerializer, 409: None},
    )
    @action(detail=False, methods=["post"], url_path="email/change/instant/verify-new")
    def email_instant_verify_new(self, request):
        serializer = self.get_instant_verify_new_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("email")
        if not new_value:
            return StapelErrorResponse(400, ERR_400_EMAIL_REQUIRED)
        svc = AuthenticatorChangeService()
        result = svc.verify_new_and_apply(
            request.user,
            "email",
            new_value,
            serializer.validated_data["code"],
            serializer.validated_data["change_token"],
        )
        if result.get("success"):
            request.user.refresh_from_db()
            access_token, refresh_token = _issue_session_tokens(request.user, request)
            tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
            auth_dto = AuthResponse(
                status=AuthStatus.MODIFIED, user=request.user, tokens=tokens_dto
            )
            response = Response(
                self.get_auth_response_serializer_class()(auth_dto).data
            )
            from stapel_core.django.utils import set_jwt_cookies

            set_jwt_cookies(response, access_token, refresh_token)
            return response
        return self._service_error_to_response(result)

    # ── Phone Delayed ────────────────────────────────────────

    @extend_schema(
        request=DelayedChangeInitiateSerializer,
        responses={201: DelayedInitiateResponseSerializer, 409: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/delayed/initiate")
    def phone_delayed_initiate(self, request):
        serializer = self.get_delayed_initiate_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("phone")
        if not new_value:
            return StapelErrorResponse(400, ERR_400_PHONE_REQUIRED)
        svc = AuthenticatorChangeService()
        from .utils import mask_value

        ip = request.headers.get("x-forwarded-for", request.META.get("REMOTE_ADDR", ""))
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()
        result = svc.initiate_delayed(
            request.user,
            "phone",
            new_value,
            device_id=serializer.validated_data.get("device_id", ""),
            ip=ip or None,
            user_agent=request.headers.get("user-agent", ""),
        )
        if result.get("success"):
            dto = DelayedInitiateResponse(
                status="PENDING",
                change_request_id=result["change_request_id"],
                new_value_masked=mask_value(new_value, "phone"),
                scheduled_at=result["scheduled_at"],
                can_cancel_until=result["scheduled_at"],
            )
            return StapelResponse(
                self.get_delayed_initiate_response_serializer_class()(dto),
                status=status.HTTP_201_CREATED,
            )
        return self._service_error_to_response(result)

    @extend_schema(responses={200: DelayedStatusResponseSerializer})
    @action(detail=False, methods=["get"], url_path="phone/change/delayed/status")
    def phone_delayed_status(self, request):
        svc = AuthenticatorChangeService()
        info = svc.get_pending_status(request.user, "phone")
        if info:
            dto = DelayedStatusResponse(has_pending_change=True, **info)
            return StapelResponse(
                self.get_delayed_status_response_serializer_class()(dto)
            )
        dto = DelayedStatusResponse(has_pending_change=False)
        return StapelResponse(self.get_delayed_status_response_serializer_class()(dto))

    @extend_schema(
        request=DelayedChangeCancelSerializer,
        responses={200: DelayedCancelResponseSerializer, 404: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/delayed/cancel")
    def phone_delayed_cancel(self, request):
        serializer = self.get_delayed_cancel_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        svc = AuthenticatorChangeService()
        result = svc.cancel_pending(
            request.user, "phone", serializer.validated_data["change_request_id"]
        )
        if result.get("success"):
            dto = DelayedCancelResponse(
                status="CANCELLED", message="Authenticator change request cancelled"
            )
            return StapelResponse(
                self.get_delayed_cancel_response_serializer_class()(dto)
            )
        return self._service_error_to_response(result)

    # ── Email Delayed ────────────────────────────────────────

    @extend_schema(
        request=DelayedChangeInitiateSerializer,
        responses={201: DelayedInitiateResponseSerializer, 409: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="email/change/delayed/initiate")
    def email_delayed_initiate(self, request):
        serializer = self.get_delayed_initiate_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("email")
        if not new_value:
            return StapelErrorResponse(400, ERR_400_EMAIL_REQUIRED)
        svc = AuthenticatorChangeService()
        from .utils import mask_value

        ip = request.headers.get("x-forwarded-for", request.META.get("REMOTE_ADDR", ""))
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()
        result = svc.initiate_delayed(
            request.user,
            "email",
            new_value,
            device_id=serializer.validated_data.get("device_id", ""),
            ip=ip or None,
            user_agent=request.headers.get("user-agent", ""),
        )
        if result.get("success"):
            dto = DelayedInitiateResponse(
                status="PENDING",
                change_request_id=result["change_request_id"],
                new_value_masked=mask_value(new_value, "email"),
                scheduled_at=result["scheduled_at"],
                can_cancel_until=result["scheduled_at"],
            )
            return StapelResponse(
                self.get_delayed_initiate_response_serializer_class()(dto),
                status=status.HTTP_201_CREATED,
            )
        return self._service_error_to_response(result)

    @extend_schema(responses={200: DelayedStatusResponseSerializer})
    @action(detail=False, methods=["get"], url_path="email/change/delayed/status")
    def email_delayed_status(self, request):
        svc = AuthenticatorChangeService()
        info = svc.get_pending_status(request.user, "email")
        if info:
            dto = DelayedStatusResponse(has_pending_change=True, **info)
            return StapelResponse(
                self.get_delayed_status_response_serializer_class()(dto)
            )
        dto = DelayedStatusResponse(has_pending_change=False)
        return StapelResponse(self.get_delayed_status_response_serializer_class()(dto))

    @extend_schema(
        request=DelayedChangeCancelSerializer,
        responses={200: DelayedCancelResponseSerializer, 404: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="email/change/delayed/cancel")
    def email_delayed_cancel(self, request):
        serializer = self.get_delayed_cancel_request_serializer_class()(
            data=request.data
        )
        serializer.is_valid(raise_exception=True)
        svc = AuthenticatorChangeService()
        result = svc.cancel_pending(
            request.user, "email", serializer.validated_data["change_request_id"]
        )
        if result.get("success"):
            dto = DelayedCancelResponse(
                status="CANCELLED", message="Authenticator change request cancelled"
            )
            return StapelResponse(
                self.get_delayed_cancel_response_serializer_class()(dto)
            )
        return self._service_error_to_response(result)


# ── Password ViewSet ──────────────────────────────────────────────────────────
