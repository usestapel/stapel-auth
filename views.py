import logging

from stapel_core.django.errors import (
    ERR_400_BAD_REQUEST,
    ERR_401_UNAUTHORIZED,
    IronErrorResponse,
    IronResponse,
    error_429_rate_limit,
    error_500_internal,
)
from stapel_core.django.openapi import (
    IronErrorSerializer,
)
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from drf_spectacular.utils import (
    OpenApiExample,
    extend_schema,
    extend_schema_view,
    inline_serializer,
)
from rest_framework import permissions, serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from .dto import (
    AuthResponse,
    AuthStatus,
    DelayedCancelResponse,
    DelayedInitiateResponse,
    DelayedStatusResponse,
    InstantRequestNewResponse,
    InstantRequestOldResponse,
    InstantVerifyOldResponse,
    LogoutResponse,
    OtpSentResponse,
    PasswordMethodsResponse,
    QRGenerateResponse,
    QRStatus,
    QRStatusResponse,
    QRType,
    TokenPairResponse,
    TokenVerifyResponse,
    TOTPChallengeResponse,
    TOTPChallengeStatus,
)
from .errors import *
from .models import LoginAttempt, ServiceAPIKey
from .serializers import (
    AnonymousAuthSerializer,
    AuthResponseSerializer,
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
    LoginResponseSerializer,
    LogoutResponseSerializer,
    OAuthSerializer,
    OtpSentResponseSerializer,
    PasswordChangeDirectSerializer,
    PasswordLoginSerializer,
    PasswordMethodsResponseSerializer,
    PasswordOtpRequestSerializer,
    PasswordOtpVerifySerializer,
    PasswordResetEmailRequestSerializer,
    PasswordResetEmailVerifySerializer,
    PasswordResetPhoneRequestSerializer,
    PasswordResetPhoneVerifySerializer,
    PhoneAuthRequestSerializer,
    PhoneAuthVerifySerializer,
    QRGenerateResponseSerializer,
    QRGenerateSerializer,
    QRStatusResponseSerializer,
    SecurityStatusResponseSerializer,
    ServiceAPIKeySerializer,
    TokenPairSerializer,
    TokenVerifyResponseSerializer,
    TokenVerifySerializer,
    TOTPChallengeResponseSerializer,
    TOTPChallengeVerifySerializer,
    TOTPDisableSerializer,
    TOTPSetupConfirmResponseSerializer,
    TOTPSetupConfirmSerializer,
    TOTPSetupResponseSerializer,
    TOTPStepUpResponseSerializer,
    TOTPStepUpSerializer,
    SimpleStatusSerializer,
    SessionResponseSerializer,
    UserSerializer,
)
from .services import (
    AuthenticatorChangeService,
    EmailVerificationService,
    OAuthService,
    PasswordService,
    PhoneVerificationService,
    QRAuthService,
)

logger = logging.getLogger(__name__)
User = get_user_model()


@extend_schema(
    tags=["Token"],
    request=inline_serializer(
        name="TokenObtainRequest",
        fields={
            "username": serializers.CharField(help_text="Username or email"),
            "password": serializers.CharField(help_text="Password"),
        },
    ),
    responses={200: TokenPairSerializer, 401: IronErrorSerializer},
)
class CustomTokenObtainPairView(APIView):
    """
    JWT token obtain view using unified jwt_provider.

    Accepts username/email and password, returns access and refresh tokens.
    """

    permission_classes = [permissions.AllowAny]

    def post(self, request):
        from stapel_core.django.jwt_provider import jwt_provider
        from stapel_core.django.utils import set_jwt_cookies

        # Accept both 'username' and 'email' as login field (for backwards compatibility)
        username = request.data.get("username") or request.data.get("email")
        password = request.data.get("password")

        if not username or not password:
            return IronErrorResponse(400, ERR_400_CREDENTIALS_REQUIRED)

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
            return IronErrorResponse(401, ERR_401_INVALID_CREDENTIALS)

        if not user.is_active:
            return IronErrorResponse(401, ERR_401_ACCOUNT_DISABLED)

        # Create tokens using jwt_provider
        access_token, refresh_token = jwt_provider.create_tokens(user)

        # Update last login
        from django.utils import timezone

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
        response = Response(
            TokenPairSerializer(tokens_dto).data, status=status.HTTP_200_OK
        )

        # Set cookies
        set_jwt_cookies(response, access_token, refresh_token)

        return response


@extend_schema_view(
    refresh_post=extend_schema(tags=["Token"]),
    refresh_get=extend_schema(tags=["Token"]),
)
class CustomTokenRefreshView(viewsets.GenericViewSet):
    """
    Custom token refresh view that checks refresh token from cookies/body
    and resets cookies with new access token
    """

    permission_classes = [permissions.AllowAny]

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
        responses={200: TokenPairSerializer, 401: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="")
    def refresh_post(self, request):
        """POST endpoint to refresh access token"""
        return self._refresh_token(request)

    @extend_schema(
        description="Refresh access token using refresh token from cookies",
        responses={200: TokenPairSerializer, 401: IronErrorSerializer},
    )
    @action(detail=False, methods=["get"], url_path="")
    def refresh_get(self, request):
        """GET endpoint to refresh access token"""
        return self._refresh_token(request)

    def _refresh_token(self, request):
        """Internal method to handle token refresh with rotation."""
        from stapel_core.django.jwt_provider import jwt_provider
        from stapel_core.django.utils import extract_jwt_from_request, set_jwt_cookies

        from .services import SessionService

        _, refresh_token_from_cookie = extract_jwt_from_request(request)
        refresh_token_from_body = (
            request.data.get("refresh") if request.method == "POST" else None
        )
        refresh_token = refresh_token_from_body or refresh_token_from_cookie

        if not refresh_token:
            return IronErrorResponse(401, ERR_401_REFRESH_NOT_PROVIDED)

        if jwt_provider.is_blacklisted(refresh_token):
            return IronErrorResponse(401, ERR_401_REFRESH_REVOKED)

        _payload = jwt_provider.handler.decode_token(refresh_token, verify=False)
        if not _payload:
            return IronErrorResponse(401, ERR_401_REFRESH_INVALID)

        old_jti = _payload.get("jti")
        _uid = _payload.get("user_id")

        from stapel_core.django.authentication import is_user_blacklisted

        if _uid and is_user_blacklisted(_uid):
            logger.warning(f"Token refresh blocked: user {_uid} is blacklisted")
            return IronErrorResponse(401, ERR_401_REFRESH_REVOKED)

        # Session-level check: reject revoked sessions
        if old_jti:
            from .models import UserSession

            session = UserSession.objects.filter(jti=old_jti).first()
            if session and session.is_revoked:
                return IronErrorResponse(401, ERR_401_REFRESH_REVOKED)

        def load_user_data(user_id: str):
            try:
                user = User.objects.get(pk=user_id)
                from stapel_core.django.utils import serialize_user_to_jwt_data

                return serialize_user_to_jwt_data(user)
            except User.DoesNotExist:
                return None

        # Issue new access token; jwt_provider also issues a new refresh token
        if old_jti:
            user_data = load_user_data(_uid)
            if not user_data:
                return IronErrorResponse(401, ERR_401_REFRESH_INVALID)
            new_access_token, new_refresh_token = jwt_provider.create_tokens_from_data(
                user_data
            )
        else:
            new_access_token = jwt_provider.refresh_access_token(
                refresh_token, load_user_data
            )
            new_refresh_token = refresh_token

        if not new_access_token:
            return IronErrorResponse(401, ERR_401_REFRESH_INVALID)

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
            at_payload = jwt_provider.handler.decode_token(new_access_token, verify=False) or {}
            rotated = SessionService.rotate(
                old_jti, new_jti, expires_at,
                user_id=_uid,
                new_access_jti=at_payload.get("jti", ""),
            )
            if rotated is None:
                return IronErrorResponse(401, ERR_401_REFRESH_REVOKED)
        else:
            new_refresh_token = refresh_token

        tokens_dto = TokenPairResponse(
            refresh=new_refresh_token, access=new_access_token
        )
        response = Response(
            TokenPairSerializer(tokens_dto).data, status=status.HTTP_200_OK
        )
        set_jwt_cookies(response, new_access_token, new_refresh_token)
        return response


_CH_HINTS = 'Sec-CH-UA-Platform-Version, Sec-CH-UA-Model'


def _add_login_hints(response, *, critical: bool = False):
    """Append UA Client Hints headers so Chromium sends real OS/model on login."""
    response['Accept-CH'] = _CH_HINTS
    if critical:
        response['Critical-CH'] = _CH_HINTS
    return response


def _issue_session_tokens(user, request):
    """Create a token pair, register a UserSession, return (access_str, refresh_str)."""
    import datetime

    from stapel_core.django.jwt_provider import jwt_provider

    from .services import AuditService, LoginNotificationService, SessionService

    access_token, refresh_token = jwt_provider.create_tokens(user)
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
        session = SessionService.create(user, jti, expires_at, request=request,
                                        access_jti=at_payload.get("jti", ""))
    AuditService.log("login_success", user=user, request=request, session=session)
    if session:
        LoginNotificationService.check_and_notify(user, session)
    return access_token, refresh_token


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
class AuthViewSet(viewsets.GenericViewSet):
    """
    ViewSet for authentication operations
    """

    permission_classes = [permissions.AllowAny]

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
            400: IronErrorSerializer,
            409: IronErrorSerializer,
            422: IronErrorSerializer,
            500: IronErrorSerializer,
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
        serializer = EmailAuthRequestSerializer(data=request.data)
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
                    return IronErrorResponse(409, ERR_409_EMAIL_TAKEN)

            # Check if email is reserved by a pending change request
            from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

            reserved = AuthenticatorChangeRequest.objects.filter(
                new_value=email,
                change_type="email",
                status=AuthenticatorChangeStatus.PENDING,
            ).exists()
            if reserved:
                return IronErrorResponse(409, ERR_409_EMAIL_RESERVED)

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
                    return IronErrorResponse(
                        422,
                        ERR_422_BLOCKED,
                        params=retry_params(verification.get("retry_after")),
                    )
            elif verification:
                dto = OtpSentResponse(
                    message="Verification code sent successfully", target=email
                )
                return IronResponse(
                    OtpSentResponseSerializer(dto), status=status.HTTP_200_OK
                )

            return IronErrorResponse(500, ERR_500_SEND_FAILED)

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
            400: IronErrorSerializer,
            409: IronErrorSerializer,
            422: IronErrorSerializer,
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
        serializer = EmailAuthVerifySerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.validated_data["email"]
            code = serializer.validated_data["code"]

            # Verify code
            verification_service = EmailVerificationService()
            result = verification_service.verify_code(email, code)

            # Handle verification errors (REJECTED status)
            if isinstance(result, dict):
                if result.get("error") == "blocked":
                    return IronErrorResponse(
                        422,
                        ERR_422_BLOCKED,
                        params=retry_params(result.get("retry_after")),
                    )
                elif result.get("error") in ("expired", "expired_retry_allowed"):
                    return IronErrorResponse(400, ERR_400_CODE_EXPIRED)
                elif result.get("error") == "invalid_code":
                    attempts_remaining = result.get("attempts_remaining")
                    self.log_login_attempt(email, "failed", request)
                    if attempts_remaining is not None:
                        return IronErrorResponse(
                            400,
                            ERR_400_INVALID_CODE_ATTEMPTS,
                            params={"attempts_remaining": attempts_remaining},
                        )
                    return IronErrorResponse(400, ERR_400_INVALID_CODE)
                elif not result.get("success"):
                    self.log_login_attempt(email, "failed", request)
                    return IronErrorResponse(400, ERR_400_INVALID_CODE)

            # Code verified successfully - determine auth status
            request_user = request.user if request.user.is_authenticated else None
            existing_user = User.objects.filter(email=email).first()
            auth_status = None
            user = None

            if request_user and not request_user.is_anonymous:
                # CASE: Authenticated non-anonymous user adding/changing email
                if existing_user and existing_user.id != request_user.id:
                    # Email belongs to another account - should not happen (checked in request)
                    return IronErrorResponse(409, ERR_409_EMAIL_TAKEN)

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
                    self._bootstrap_personal_workspace(user)
                    auth_status = AuthStatus.REGISTERED

            self.log_login_attempt(email, "success", request)
            access_token, refresh_token = _issue_session_tokens(user, request)
            tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
            auth_dto = AuthResponse(status=auth_status, user=user, tokens=tokens_dto)
            response = Response(
                AuthResponseSerializer(auth_dto).data, status=status.HTTP_200_OK
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
            400: IronErrorSerializer,
            409: IronErrorSerializer,
            422: IronErrorSerializer,
            500: IronErrorSerializer,
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
        serializer = PhoneAuthRequestSerializer(data=request.data)
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
                    return IronErrorResponse(409, ERR_409_PHONE_TAKEN)

            # Check if phone is reserved by a pending change request
            from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

            reserved = AuthenticatorChangeRequest.objects.filter(
                new_value=phone,
                change_type="phone",
                status=AuthenticatorChangeStatus.PENDING,
            ).exists()
            if reserved:
                return IronErrorResponse(409, ERR_409_PHONE_RESERVED)

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
                    return IronErrorResponse(
                        422,
                        ERR_422_BLOCKED,
                        params=retry_params(verification.get("retry_after")),
                    )
            elif verification:
                dto = OtpSentResponse(
                    message="Verification code sent successfully", target=phone
                )
                return IronResponse(
                    OtpSentResponseSerializer(dto), status=status.HTTP_200_OK
                )

            return IronErrorResponse(500, ERR_500_SEND_FAILED)

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
            400: IronErrorSerializer,
            409: IronErrorSerializer,
            422: IronErrorSerializer,
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
        serializer = PhoneAuthVerifySerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            phone = serializer.validated_data["phone"]
            code = serializer.validated_data["code"]

            # Verify code
            verification_service = PhoneVerificationService()
            result = verification_service.verify_code(phone, code)

            # Handle verification errors (REJECTED status)
            if isinstance(result, dict):
                if result.get("error") == "blocked":
                    return IronErrorResponse(
                        422,
                        ERR_422_BLOCKED,
                        params=retry_params(result.get("retry_after")),
                    )
                elif result.get("error") in ("expired", "expired_retry_allowed"):
                    return IronErrorResponse(400, ERR_400_CODE_EXPIRED)
                elif result.get("error") == "invalid_code":
                    attempts_remaining = result.get("attempts_remaining")
                    self.log_login_attempt(phone, "failed", request)
                    if attempts_remaining is not None:
                        return IronErrorResponse(
                            400,
                            ERR_400_INVALID_CODE_ATTEMPTS,
                            params={"attempts_remaining": attempts_remaining},
                        )
                    return IronErrorResponse(400, ERR_400_INVALID_CODE)
                elif not result.get("success"):
                    self.log_login_attempt(phone, "failed", request)
                    return IronErrorResponse(400, ERR_400_INVALID_CODE)

            # Code verified successfully - determine auth status
            request_user = request.user if request.user.is_authenticated else None
            existing_user = User.objects.filter(phone=phone).first()
            auth_status = None
            user = None

            if request_user and not request_user.is_anonymous:
                # CASE: Authenticated non-anonymous user adding/changing phone
                if existing_user and existing_user.id != request_user.id:
                    # Phone belongs to another account - should not happen (checked in request)
                    return IronErrorResponse(409, ERR_409_PHONE_TAKEN)

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
                AuthResponseSerializer(auth_dto).data, status=status.HTTP_200_OK
            )
            from stapel_core.django.utils import set_jwt_cookies

            set_jwt_cookies(response, access_token, refresh_token)
            return _add_login_hints(response)

    @extend_schema(
        description="Create anonymous user",
        request=AnonymousAuthSerializer,
        responses={201: AuthResponseSerializer, 400: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"])
    def anonymous(self, request):
        """Create anonymous user (or return existing anonymous session)."""
        serializer = AnonymousAuthSerializer(data=request.data)
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
                AuthResponseSerializer(auth_dto).data, status=status.HTTP_201_CREATED
            )
            from stapel_core.django.utils import set_jwt_cookies

            set_jwt_cookies(response, access_token, refresh_token)
            return response

    @extend_schema(
        description="OAuth authentication (Google, Facebook, etc.). Returns `LoginResponse` — either `AuthResponse` (status=LOGGED_IN) or `TOTPChallengeResponse` (status=TOTP_REQUIRED). When TOTP is required, pass `challenge_token` to `POST /totp/challenge/verify/`.",
        request=OAuthSerializer,
        responses={200: LoginResponseSerializer, 400: IronErrorSerializer},
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
        provider = request.data.get("provider")
        access_token = request.data.get("access_token")

        if not provider or not access_token:
            return IronErrorResponse(400, ERR_400_OAUTH_FIELDS_REQUIRED)

        ocore = OAuthService()
        user_data = ocore.get_user_data(provider, access_token)

        if not user_data:
            return IronErrorResponse(400, ERR_400_OAUTH_FAILED)

        user = self._resolve_oauth_user(provider, user_data)
        self.log_login_attempt(str(user.id), "success", request)

        from .services import TOTPService

        if TOTPService.is_enabled(user):
            challenge_token = TOTPService.create_challenge(str(user.id))
            dto = TOTPChallengeResponse(
                status=TOTPChallengeStatus.TOTP_REQUIRED,
                challenge_token=challenge_token,
                expires_in=TOTPService.CHALLENGE_TTL,
            )
            return IronResponse(TOTPChallengeResponseSerializer(dto))

        access_token, refresh_token = _issue_session_tokens(user, request)
        tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
        auth_dto = AuthResponse(
            status=AuthStatus.LOGGED_IN, user=user, tokens=tokens_dto
        )
        response = Response(
            AuthResponseSerializer(auth_dto).data, status=status.HTTP_200_OK
        )
        from stapel_core.django.utils import set_jwt_cookies

        set_jwt_cookies(response, access_token, refresh_token)
        return _add_login_hints(response)

    _OAUTH_PROVIDERS = {
        "google": {
            "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "client_id_setting": "SOCIAL_AUTH_GOOGLE_OAUTH2_KEY",
            "client_secret_setting": "SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET",
            "scope": "openid email profile",
            "extra_params": {"access_type": "offline"},
        },
        "github": {
            "auth_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "client_id_setting": "SOCIAL_AUTH_GITHUB_KEY",
            "client_secret_setting": "SOCIAL_AUTH_GITHUB_SECRET",
            "scope": "read:user user:email",
            "extra_params": {},
        },
        "zoom": {
            "auth_url": "https://zoom.us/oauth/authorize",
            "token_url": "https://zoom.us/oauth/token",
            "client_id_setting": "ZOOM_CLIENT_ID",
            "client_secret_setting": "ZOOM_CLIENT_SECRET",
            "scope": "user:read:user",
            "extra_params": {},
        },
    }

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
        from urllib.parse import urlencode

        from django.core.cache import cache
        from django.shortcuts import redirect

        if provider not in self._OAUTH_PROVIDERS:
            return IronErrorResponse(400, ERR_400_OAUTH_FAILED)

        config = self._OAUTH_PROVIDERS[provider]
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

        params = {
            "client_id": getattr(settings, config["client_id_setting"], ""),
            "redirect_uri": redirect_uri,
            "scope": config["scope"],
            "state": state,
            "response_type": "code",
            **config["extra_params"],
        }
        return redirect(config["auth_url"] + "?" + urlencode(params))

    @extend_schema(
        description="OAuth provider callback — exchanges code for JWT and redirects to frontend",
        responses={302: None, 400: IronErrorSerializer},
    )
    @action(
        detail=False, methods=["get"], url_path="oauth/(?P<provider>[^/.]+)/callback"
    )
    def oauth_callback(self, request, provider=None):
        """Handle OAuth authorization code callback"""
        from urllib.parse import urlencode

        import requests as http
        from django.core.cache import cache
        from django.shortcuts import redirect

        error = request.query_params.get("error")
        code = request.query_params.get("code")
        state = request.query_params.get("state")

        if error or not code or not state:
            return IronErrorResponse(400, ERR_400_OAUTH_FAILED)

        state_data = cache.get(f"oauth_state:{state}")
        if not state_data or state_data.get("provider") != provider:
            return IronErrorResponse(400, ERR_400_OAUTH_FAILED)
        cache.delete(f"oauth_state:{state}")

        if provider not in self._OAUTH_PROVIDERS:
            return IronErrorResponse(400, ERR_400_OAUTH_FAILED)

        config = self._OAUTH_PROVIDERS[provider]
        redirect_uri = state_data["redirect_uri"]

        # Exchange authorization code for access token
        token_response = http.post(
            config["token_url"],
            data={
                "code": code,
                "client_id": getattr(settings, config["client_id_setting"], ""),
                "client_secret": getattr(settings, config["client_secret_setting"], ""),
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
            headers={"Accept": "application/json"},
        )
        if token_response.status_code != 200:
            return IronErrorResponse(400, ERR_400_OAUTH_FAILED)

        access_token = token_response.json().get("access_token")
        if not access_token:
            return IronErrorResponse(400, ERR_400_OAUTH_FAILED)

        ocore = OAuthService()
        user_data = ocore.get_user_data(provider, access_token)
        if not user_data:
            return IronErrorResponse(400, ERR_400_OAUTH_FAILED)

        user = self._resolve_oauth_user(provider, user_data)
        self.log_login_attempt(str(user.id), "success", request)

        from .services import TOTPService

        if TOTPService.is_enabled(user):
            challenge_token = TOTPService.create_challenge(str(user.id))
            redirect_after = state_data.get("redirect_after", "")
            # Encode redirect_after inside the TOTP challenge URL so the
            # frontend can resume the OAuth redirect flow after TOTP verify.
            params = {"token": challenge_token}
            if redirect_after:
                params["redirect_after"] = redirect_after
            return redirect("/totp-challenge?" + urlencode(params))

        access_token, refresh_token = _issue_session_tokens(user, request)

        redirect_after = state_data.get("redirect_after", "")
        if redirect_after:
            params = urlencode(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                }
            )
            return redirect(f"{redirect_after}?{params}")

        tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
        auth_dto = AuthResponse(
            status=AuthStatus.LOGGED_IN, user=user, tokens=tokens_dto
        )
        response = Response(
            AuthResponseSerializer(auth_dto).data, status=status.HTTP_200_OK
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
        oauth_id = str(user_data["id"])
        email = user_data.get("email")

        # 1. Exact provider match
        try:
            return User.objects.get(oauth_provider=provider, oauth_id=oauth_id)
        except User.DoesNotExist:
            pass

        # 2. Same verified email → merge into existing account
        if email:
            try:
                return User.objects.get(email=email)
            except User.DoesNotExist:
                pass

        # 3. Brand-new user
        user = User.objects.create(
            email=email,
            oauth_provider=provider,
            oauth_id=oauth_id,
            auth_type="oauth",
            avatar=user_data.get("avatar"),
            is_email_verified=True,
        )
        self._bootstrap_personal_workspace(user)
        return user

    def _bootstrap_personal_workspace(self, user) -> None:
        """Fire-and-forget: create personal workspace for newly registered users."""
        try:
            from stapel_core.django.workspaces import get_or_create_personal_workspace

            get_or_create_personal_workspace(user.id)
        except Exception:
            logger.exception(
                "Failed to bootstrap personal workspace for user %s", user.id
            )

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
        responses={200: LogoutResponseSerializer, 400: IronErrorSerializer},
    )
    @action(
        detail=False, methods=["post"], permission_classes=[permissions.IsAuthenticated]
    )
    def logout(self, request):
        """POST endpoint to logout user"""
        return self._logout(request)

    @extend_schema(
        description="Logout user via GET request (for cookie-based authentication). Blacklists both access and refresh tokens.",
        responses={200: LogoutResponseSerializer, 400: IronErrorSerializer},
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
            from django.core.cache import cache

            # Extract tokens from cookies/headers
            access_token, refresh_token_cookie = extract_jwt_from_request(request)

            # Also check request body for refresh token (POST only)
            refresh_token_body = None
            if request.method == "POST":
                refresh_token_body = request.data.get("refresh_token")

            # Use cookie refresh token if body not provided
            refresh_token = refresh_token_body or refresh_token_cookie

            # Initialize Redis blacklist - use django-redis cache client
            redis_client = None
            try:
                if hasattr(cache, "client"):
                    redis_client = cache.client.get_client()
                    logger.info(f"Redis client for logout: {type(redis_client)}")
            except Exception as e:
                logger.warning(f"Failed to get Redis client from cache: {e}")

            blacklist = TokenBlacklist(redis_client)
            logger.info(f"Blacklist enabled: {blacklist._enabled}")

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
                LogoutResponseSerializer(dto).data, status=status.HTTP_200_OK
            )

            # Clear JWT cookies
            cookie_name = getattr(settings, "JWT_COOKIE_NAME", "iron_jwt")
            refresh_cookie_name = getattr(
                settings, "JWT_REFRESH_COOKIE_NAME", "iron_refresh_jwt"
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
        responses={200: UserSerializer, 401: IronErrorSerializer},
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
            jwt_cookie = request.COOKIES.get("iron_jwt", "")
            refresh_cookie = request.COOKIES.get("iron_refresh_jwt", "")

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

            resp = IronErrorResponse(401, ERR_401_UNAUTHORIZED)
            resp['Accept-CH'] = _CH_HINTS
            return resp

        serializer = UserSerializer(request.user)
        resp = IronResponse(serializer)
        resp['Accept-CH'] = _CH_HINTS
        return resp

    @extend_schema(
        description="Verify JWT token",
        request=TokenVerifySerializer,
        responses={200: TokenVerifyResponseSerializer, 401: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"])
    def verify_token(self, request):
        """Verify JWT token"""
        from stapel_core.django.jwt_provider import jwt_provider

        token = request.data.get("token")
        if not token:
            return IronErrorResponse(400, ERR_400_TOKEN_REQUIRED)

        try:
            # Validate token using jwt_provider
            payload = jwt_provider.validate_token(token)

            if not payload:
                return IronErrorResponse(401, ERR_401_TOKEN_INVALID)

            # Check if blacklisted
            if jwt_provider.is_blacklisted(token):
                return IronErrorResponse(401, ERR_401_TOKEN_REVOKED)

            user_id = payload.get("user_id")
            user = User.objects.get(id=user_id)

            verify_dto = TokenVerifyResponse(valid=True, user=user)
            return IronResponse(
                TokenVerifyResponseSerializer(verify_dto), status=status.HTTP_200_OK
            )
        except User.DoesNotExist:
            return IronErrorResponse(401, ERR_401_USER_NOT_FOUND)
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return IronErrorResponse(401, ERR_401_TOKEN_INVALID)


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


class JWKSView(viewsets.GenericViewSet):
    """
    JSON Web Key Set (JWKS) endpoint.

    Provides the public key(s) for JWT verification in standard JWKS format.
    This endpoint is used by other services and external clients to verify tokens
    issued by this auth service.

    For HS256 (symmetric): Returns algorithm info but no key (key cannot be shared).
    For RS256 (asymmetric): Returns the public key in JWK format.

    Note: This endpoint is excluded from Swagger/OpenAPI documentation as it's
    a standard discovery endpoint accessed directly via /.well-known/jwks.json
    """

    permission_classes = [permissions.AllowAny]
    schema = None  # Exclude from OpenAPI schema generation

    @action(detail=False, methods=["get"], url_path="")
    def jwks(self, request):
        """Return JWKS for token verification."""
        from stapel_core.django.jwt_provider import jwt_provider

        config = jwt_provider.config
        algorithm = config.algorithm
        issuer = config.issuer

        if algorithm == "RS256":
            # RS256 mode - return public key in JWKS format
            try:
                jwks = jwt_provider.get_jwks()

                if jwks:
                    return IronResponse(jwks, status=status.HTTP_200_OK)
                else:
                    return IronResponse(  # noqa: R006
                        {"keys": [], "error": "Public key not available"},
                        status=status.HTTP_200_OK,
                    )
            except Exception as e:
                logger.error(f"Failed to generate JWKS: {e}")
                return IronResponse(  # noqa: R006
                    {"keys": [], "error": str(e)},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        else:
            # HS256 mode - cannot share symmetric keyk
            return IronResponse(  # noqa: R006
                {
                    "keys": [],
                    "_info": {
                        "algorithm": algorithm,
                        "issuer": issuer,
                        "note": "HS256 uses symmetric key which cannot be shared via JWKS. "
                        "Use the same JWT_SECRET_KEY configured in all services.",
                    },
                },
                status=status.HTTP_200_OK,
            )


class OpenIDConfigurationView(viewsets.GenericViewSet):
    """
    OpenID Connect Discovery endpoint.

    Provides the OpenID Connect configuration for token verification.
    This is the standard .well-known/openid-configuration endpoint.

    Note: This endpoint is excluded from Swagger/OpenAPI documentation as it's
    a standard discovery endpoint accessed directly via /.well-known/openid-configuration
    """

    permission_classes = [permissions.AllowAny]
    schema = None  # Exclude from OpenAPI schema generation

    @action(detail=False, methods=["get"], url_path="")
    def openid_configuration(self, request):
        """Return OpenID Connect configuration."""
        from stapel_core.django.jwt_provider import jwt_provider

        config = jwt_provider.config
        algorithm = config.algorithm
        issuer = config.issuer

        # Build base URL from request
        scheme = request.scheme
        host = request.get_host()
        base_url = f"{scheme}://{host}"

        url_prefix = getattr(settings, "URL_PREFIX", "")

        config = {
            "issuer": issuer,
            "jwks_uri": f"{base_url}/{url_prefix}.well-known/jwks.json",
            "token_endpoint": f"{base_url}/{url_prefix}api/auth/token/",
            "token_refresh_endpoint": f"{base_url}/{url_prefix}api/auth/token/refresh/",
            "userinfo_endpoint": f"{base_url}/{url_prefix}api/auth/me/",
            "response_types_supported": ["token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [algorithm],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
            "claims_supported": [
                "sub",
                "user_id",
                "email",
                "username",
                "iss",
                "exp",
                "iat",
                "jti",
                "token_type",
                "auth_type",
                "is_anonymous",
                "is_staff",
                "is_superuser",
            ],
        }

        return IronResponse(config, status=status.HTTP_200_OK)


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
class AuthenticatorChangeViewSet(viewsets.GenericViewSet):
    """ViewSet for authenticator (phone/email) change flows."""

    permission_classes = [permissions.IsAuthenticated]

    def _service_error_to_response(self, result):
        """Convert service error dict to IronErrorResponse."""
        error = result.get("error", "unknown_error")

        if error == "rate_limit":
            return error_429_rate_limit(result.get("retry_after"))
        if error == "blocked":
            return IronErrorResponse(
                422,
                ERR_422_BLOCKED,
                params=retry_params(result.get("retry_after")),
            )
        if error == "not_available":
            return IronErrorResponse(409, ERR_400_NOT_AVAILABLE)
        if error == "no_current_value":
            return IronErrorResponse(400, ERR_400_NO_CURRENT_VALUE)
        if error in ("invalid_change_token", "value_mismatch"):
            return IronErrorResponse(400, ERR_400_INVALID_CHANGE_TOKEN)
        if error == "not_found":
            return IronErrorResponse(404, ERR_404_CHANGE_NOT_FOUND)
        if error == "invalid_code":
            return IronErrorResponse(
                400,
                ERR_400_INVALID_CODE,
                params={"attempts_remaining": result.get("attempts_remaining")},
            )
        if error in ("expired", "expired_retry_allowed"):
            return IronErrorResponse(400, ERR_400_CODE_EXPIRED)
        if error == "send_failed":
            return IronErrorResponse(500, ERR_500_SEND_FAILED)

        return IronErrorResponse(400, ERR_400_BAD_REQUEST)

    # ── Phone Instant ────────────────────────────────────────

    @extend_schema(
        request=InstantChangeRequestOldSerializer,
        responses={200: InstantRequestOldResponseSerializer},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/instant/request-old")
    def phone_instant_request_old(self, request):
        serializer = InstantChangeRequestOldSerializer(data=request.data)
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
            return IronResponse(InstantRequestOldResponseSerializer(dto))
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeVerifyOldSerializer,
        responses={200: InstantVerifyOldResponseSerializer},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/instant/verify-old")
    def phone_instant_verify_old(self, request):
        serializer = InstantChangeVerifyOldSerializer(data=request.data)
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
            return IronResponse(InstantVerifyOldResponseSerializer(dto))
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeRequestNewSerializer,
        responses={200: InstantRequestNewResponseSerializer, 409: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/instant/request-new")
    def phone_instant_request_new(self, request):
        serializer = InstantChangeRequestNewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("phone")
        if not new_value:
            return IronErrorResponse(400, ERR_400_PHONE_REQUIRED)
        svc = AuthenticatorChangeService()
        result = svc.request_new_otp(
            request.user, "phone", new_value, serializer.validated_data["change_token"]
        )
        if result.get("success"):
            dto = InstantRequestNewResponse(
                message="Verification code sent to new phone"
            )
            return IronResponse(InstantRequestNewResponseSerializer(dto))
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeVerifyNewSerializer,
        responses={200: AuthResponseSerializer, 409: None},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/instant/verify-new")
    def phone_instant_verify_new(self, request):
        serializer = InstantChangeVerifyNewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("phone")
        if not new_value:
            return IronErrorResponse(400, ERR_400_PHONE_REQUIRED)
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
            response = Response(AuthResponseSerializer(auth_dto).data)
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
        serializer = InstantChangeRequestOldSerializer(data=request.data)
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
            return IronResponse(InstantRequestOldResponseSerializer(dto))
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeVerifyOldSerializer,
        responses={200: InstantVerifyOldResponseSerializer},
    )
    @action(detail=False, methods=["post"], url_path="email/change/instant/verify-old")
    def email_instant_verify_old(self, request):
        serializer = InstantChangeVerifyOldSerializer(data=request.data)
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
            return IronResponse(InstantVerifyOldResponseSerializer(dto))
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeRequestNewSerializer,
        responses={200: InstantRequestNewResponseSerializer, 409: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="email/change/instant/request-new")
    def email_instant_request_new(self, request):
        serializer = InstantChangeRequestNewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("email")
        if not new_value:
            return IronErrorResponse(400, ERR_400_EMAIL_REQUIRED)
        svc = AuthenticatorChangeService()
        result = svc.request_new_otp(
            request.user, "email", new_value, serializer.validated_data["change_token"]
        )
        if result.get("success"):
            dto = InstantRequestNewResponse(
                message="Verification code sent to new email"
            )
            return IronResponse(InstantRequestNewResponseSerializer(dto))
        return self._service_error_to_response(result)

    @extend_schema(
        request=InstantChangeVerifyNewSerializer,
        responses={200: AuthResponseSerializer, 409: None},
    )
    @action(detail=False, methods=["post"], url_path="email/change/instant/verify-new")
    def email_instant_verify_new(self, request):
        serializer = InstantChangeVerifyNewSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("email")
        if not new_value:
            return IronErrorResponse(400, ERR_400_EMAIL_REQUIRED)
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
            response = Response(AuthResponseSerializer(auth_dto).data)
            from stapel_core.django.utils import set_jwt_cookies

            set_jwt_cookies(response, access_token, refresh_token)
            return response
        return self._service_error_to_response(result)

    # ── Phone Delayed ────────────────────────────────────────

    @extend_schema(
        request=DelayedChangeInitiateSerializer,
        responses={201: DelayedInitiateResponseSerializer, 409: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/delayed/initiate")
    def phone_delayed_initiate(self, request):
        serializer = DelayedChangeInitiateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("phone")
        if not new_value:
            return IronErrorResponse(400, ERR_400_PHONE_REQUIRED)
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
            return IronResponse(
                DelayedInitiateResponseSerializer(dto), status=status.HTTP_201_CREATED
            )
        return self._service_error_to_response(result)

    @extend_schema(responses={200: DelayedStatusResponseSerializer})
    @action(detail=False, methods=["get"], url_path="phone/change/delayed/status")
    def phone_delayed_status(self, request):
        svc = AuthenticatorChangeService()
        info = svc.get_pending_status(request.user, "phone")
        if info:
            dto = DelayedStatusResponse(has_pending_change=True, **info)
            return IronResponse(DelayedStatusResponseSerializer(dto))
        dto = DelayedStatusResponse(has_pending_change=False)
        return IronResponse(DelayedStatusResponseSerializer(dto))

    @extend_schema(
        request=DelayedChangeCancelSerializer,
        responses={200: DelayedCancelResponseSerializer, 404: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="phone/change/delayed/cancel")
    def phone_delayed_cancel(self, request):
        serializer = DelayedChangeCancelSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        svc = AuthenticatorChangeService()
        result = svc.cancel_pending(
            request.user, "phone", serializer.validated_data["change_request_id"]
        )
        if result.get("success"):
            dto = DelayedCancelResponse(
                status="CANCELLED", message="Authenticator change request cancelled"
            )
            return IronResponse(DelayedCancelResponseSerializer(dto))
        return self._service_error_to_response(result)

    # ── Email Delayed ────────────────────────────────────────

    @extend_schema(
        request=DelayedChangeInitiateSerializer,
        responses={201: DelayedInitiateResponseSerializer, 409: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="email/change/delayed/initiate")
    def email_delayed_initiate(self, request):
        serializer = DelayedChangeInitiateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_value = serializer.validated_data.get("email")
        if not new_value:
            return IronErrorResponse(400, ERR_400_EMAIL_REQUIRED)
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
            return IronResponse(
                DelayedInitiateResponseSerializer(dto), status=status.HTTP_201_CREATED
            )
        return self._service_error_to_response(result)

    @extend_schema(responses={200: DelayedStatusResponseSerializer})
    @action(detail=False, methods=["get"], url_path="email/change/delayed/status")
    def email_delayed_status(self, request):
        svc = AuthenticatorChangeService()
        info = svc.get_pending_status(request.user, "email")
        if info:
            dto = DelayedStatusResponse(has_pending_change=True, **info)
            return IronResponse(DelayedStatusResponseSerializer(dto))
        dto = DelayedStatusResponse(has_pending_change=False)
        return IronResponse(DelayedStatusResponseSerializer(dto))

    @extend_schema(
        request=DelayedChangeCancelSerializer,
        responses={200: DelayedCancelResponseSerializer, 404: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="email/change/delayed/cancel")
    def email_delayed_cancel(self, request):
        serializer = DelayedChangeCancelSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        svc = AuthenticatorChangeService()
        result = svc.cancel_pending(
            request.user, "email", serializer.validated_data["change_request_id"]
        )
        if result.get("success"):
            dto = DelayedCancelResponse(
                status="CANCELLED", message="Authenticator change request cancelled"
            )
            return IronResponse(DelayedCancelResponseSerializer(dto))
        return self._service_error_to_response(result)


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
class PasswordViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.AllowAny]

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
        responses={200: LoginResponseSerializer, 401: IronErrorSerializer},
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="login",
        permission_classes=[permissions.AllowAny],
    )
    def login(self, request):
        from stapel_core.django.utils import set_jwt_cookies
        from django.utils import timezone

        from .errors import ERR_423_ACCOUNT_LOCKED, retry_params
        from .services import AuditService, LockoutService

        serializer = PasswordLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        identifier = serializer.validated_data["login"]

        is_locked, retry_after = LockoutService.check(identifier)
        if is_locked:
            return IronErrorResponse(
                423, ERR_423_ACCOUNT_LOCKED, params=retry_params(retry_after)
            )

        user = PasswordService.login(identifier, serializer.validated_data["password"])
        if user is None:
            count = LockoutService.record_failure(identifier)
            duration = LockoutService.apply_lockout(identifier, count, request=request)
            if duration:
                return IronErrorResponse(
                    423, ERR_423_ACCOUNT_LOCKED, params=retry_params(duration)
                )
            AuditService.log("login_failed", request=request, identifier=identifier)
            return IronErrorResponse(401, ERR_401_INVALID_CREDENTIALS)
        if not user.is_active:
            AuditService.log(
                "login_failed", user=user, request=request, reason="account_disabled"
            )
            return IronErrorResponse(401, ERR_401_ACCOUNT_DISABLED)

        LockoutService.clear(identifier)

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        from .services import TOTPService

        if TOTPService.is_enabled(user):
            challenge_token = TOTPService.create_challenge(str(user.id))
            dto = TOTPChallengeResponse(
                status=TOTPChallengeStatus.TOTP_REQUIRED,
                challenge_token=challenge_token,
                expires_in=TOTPService.CHALLENGE_TTL,
            )
            return IronResponse(TOTPChallengeResponseSerializer(dto))

        access_token, refresh_token = _issue_session_tokens(user, request)
        dto = AuthResponse(
            status=AuthStatus.LOGGED_IN,
            user=user,
            tokens=TokenPairResponse(refresh=refresh_token, access=access_token),
        )
        response = Response(AuthResponseSerializer(dto).data)
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
        return IronResponse(PasswordMethodsResponseSerializer(dto))

    @extend_schema(
        description="Change password by providing the current password.",
        request=PasswordChangeDirectSerializer,
        responses={200: None, 400: IronErrorSerializer},
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="change",
        permission_classes=[permissions.IsAuthenticated],
    )
    def change_direct(self, request):
        if not request.user.has_usable_password():
            return IronErrorResponse(400, ERR_400_NO_PASSWORD)
        serializer = PasswordChangeDirectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ok = PasswordService.change_via_old(
            request.user,
            serializer.validated_data["old_password"],
            serializer.validated_data["new_password"],
        )
        if not ok:
            return IronErrorResponse(400, ERR_400_WRONG_PASSWORD)
        from .dto import SimpleStatusResponse
        return IronResponse(SimpleStatusSerializer(SimpleStatusResponse(status='password_changed')))

    @extend_schema(
        description="Request OTP to own verified email or phone in order to change password.",
        request=PasswordOtpRequestSerializer,
        responses={
            200: OtpSentResponseSerializer,
            400: IronErrorSerializer,
            422: IronErrorSerializer,
            429: IronErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="change/otp/request",
        permission_classes=[permissions.IsAuthenticated],
    )
    def change_otp_request(self, request):
        serializer = PasswordOtpRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        masked = PasswordService.send_change_otp(
            request.user, serializer.validated_data["method"]
        )
        dto = OtpSentResponse(message="Verification code sent", target=masked)
        return IronResponse(OtpSentResponseSerializer(dto))

    @extend_schema(
        description="Verify OTP and set new password (for authenticated users).",
        request=PasswordOtpVerifySerializer,
        responses={200: None, 400: IronErrorSerializer},
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="change/otp/verify",
        permission_classes=[permissions.IsAuthenticated],
    )
    def change_otp_verify(self, request):
        serializer = PasswordOtpVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        PasswordService.change_via_otp(
            request.user,
            method=serializer.validated_data["method"],
            code=serializer.validated_data["code"],
            new_password=serializer.validated_data["new_password"],
        )
        from .dto import SimpleStatusResponse
        return IronResponse(SimpleStatusSerializer(SimpleStatusResponse(status='password_changed')))

    @extend_schema(
        description="Request OTP to verified email to reset a forgotten password (unauthenticated).",
        request=PasswordResetEmailRequestSerializer,
        responses={
            200: OtpSentResponseSerializer,
            403: IronErrorSerializer,
            404: IronErrorSerializer,
            429: IronErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="reset/email/request",
        permission_classes=[permissions.AllowAny],
    )
    def reset_email_request(self, request):
        serializer = PasswordResetEmailRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        masked = PasswordService.reset_request(email=serializer.validated_data["email"])
        return IronResponse(
            OtpSentResponseSerializer(
                OtpSentResponse(message="Verification code sent", target=masked)
            )
        )

    @extend_schema(
        description="Verify email OTP and set new password. Returns tokens — the user is logged in.",
        request=PasswordResetEmailVerifySerializer,
        responses={
            200: AuthResponseSerializer,
            400: IronErrorSerializer,
            404: IronErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="reset/email/verify",
        permission_classes=[permissions.AllowAny],
    )
    def reset_email_verify(self, request):
        from stapel_core.django.jwt_provider import jwt_provider
        from stapel_core.django.utils import set_jwt_cookies

        serializer = PasswordResetEmailVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = PasswordService.reset_verify(
            email=serializer.validated_data["email"],
            code=serializer.validated_data["code"],
            new_password=serializer.validated_data["new_password"],
        )
        access_token, refresh_token = jwt_provider.create_tokens(user)
        dto = AuthResponse(
            status=AuthStatus.LOGGED_IN,
            user=user,
            tokens=TokenPairResponse(refresh=refresh_token, access=access_token),
        )
        response = Response(AuthResponseSerializer(dto).data)
        set_jwt_cookies(response, access_token, refresh_token)
        return response

    @extend_schema(
        description="Request OTP to verified phone to reset a forgotten password (unauthenticated).",
        request=PasswordResetPhoneRequestSerializer,
        responses={
            200: OtpSentResponseSerializer,
            403: IronErrorSerializer,
            404: IronErrorSerializer,
            429: IronErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="reset/phone/request",
        permission_classes=[permissions.AllowAny],
    )
    def reset_phone_request(self, request):
        serializer = PasswordResetPhoneRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        masked = PasswordService.reset_request(phone=serializer.validated_data["phone"])
        return IronResponse(
            OtpSentResponseSerializer(
                OtpSentResponse(message="Verification code sent", target=masked)
            )
        )

    @extend_schema(
        description="Verify phone OTP and set new password. Returns tokens — the user is logged in.",
        request=PasswordResetPhoneVerifySerializer,
        responses={
            200: AuthResponseSerializer,
            400: IronErrorSerializer,
            404: IronErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="reset/phone/verify",
        permission_classes=[permissions.AllowAny],
    )
    def reset_phone_verify(self, request):
        from stapel_core.django.jwt_provider import jwt_provider
        from stapel_core.django.utils import set_jwt_cookies

        serializer = PasswordResetPhoneVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = PasswordService.reset_verify(
            phone=serializer.validated_data["phone"],
            code=serializer.validated_data["code"],
            new_password=serializer.validated_data["new_password"],
        )
        access_token, refresh_token = jwt_provider.create_tokens(user)
        dto = AuthResponse(
            status=AuthStatus.LOGGED_IN,
            user=user,
            tokens=TokenPairResponse(refresh=refresh_token, access=access_token),
        )
        response = Response(AuthResponseSerializer(dto).data)
        set_jwt_cookies(response, access_token, refresh_token)
        return response


# ── QR Auth ViewSet ───────────────────────────────────────────────────────────


@extend_schema_view(
    generate=extend_schema(tags=["QR Auth"]),
    qr_status=extend_schema(tags=["QR Auth"]),
    scan=extend_schema(tags=["QR Auth"]),
    confirm=extend_schema(tags=["QR Auth"]),
)
class QRAuthViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.AllowAny]

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
            400: IronErrorSerializer,
            401: IronErrorSerializer,
        },
    )
    @action(detail=False, methods=["post"], url_path="generate")
    def generate(self, request):
        serializer = QRGenerateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        qr_type = serializer.validated_data["type"]
        redirect_url = serializer.validated_data.get("redirect_url")

        if qr_type == QRType.SESSION_SHARE and not request.user.is_authenticated:
            return IronErrorResponse(401, ERR_401_QR_AUTH_REQUIRED)

        owner_user_id = request.user.id if request.user.is_authenticated else None
        key = QRAuthService.generate(
            qr_type=qr_type,
            owner_user_id=owner_user_id,
            redirect_url=redirect_url,
        )

        scan_url = request.build_absolute_uri(f"/auth/api/qr/{key}/scan/")
        dto = QRGenerateResponse(
            key=key,
            type=qr_type,
            expires_in=self.QR_TTL,
            scan_url=scan_url,
        )
        return IronResponse(
            QRGenerateResponseSerializer(dto), status=status.HTTP_201_CREATED
        )

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
        data = QRAuthService.get(key)
        if data is None:
            dto = QRStatusResponse(status=QRStatus.EXPIRED)
            return IronResponse(QRStatusResponseSerializer(dto))

        if data["status"] == QRStatus.REJECTED:
            return IronResponse(QRStatusResponseSerializer(QRStatusResponse(status=QRStatus.REJECTED)))

        if data["status"] == QRStatus.FULFILLED:
            access_token = data.get("access_token")
            refresh_token = data.get("refresh_token")
            # Create session for the polling device (once — key is deleted after)
            if access_token and data.get("fulfilled_user_id"):
                try:
                    from datetime import datetime, timezone as _tz
                    from django.contrib.auth import get_user_model as _gum
                    from stapel_core.django.jwt_provider import jwt_provider as _jwt
                    _rt = data.get("refresh_token", "")
                    _rt_pl = _jwt.handler.decode_token(_rt, verify=False) or {}
                    _at_pl = _jwt.handler.decode_token(access_token, verify=False) or {}
                    _jti  = _rt_pl.get("jti", "")
                    _exp  = datetime.fromtimestamp(_rt_pl.get("exp", 0), tz=_tz.utc)
                    _user = _gum().objects.filter(pk=data["fulfilled_user_id"]).first()
                    if _user and _jti:
                        from .services import SessionService as _SS, AuditService as _AS, LoginNotificationService as _LNS
                        _session = _SS.create(_user, _jti, _exp, request=request,
                                              access_jti=_at_pl.get("jti", ""))
                        _AS.log('login_success', user=_user, request=request, session=_session)
                        if _session:
                            _LNS.check_and_notify(_user, _session)
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

        return IronResponse(QRStatusResponseSerializer(dto))

    @extend_schema(
        description="""Browser endpoint embedded in QR code. Processes the scan and redirects.

**session_share** (scanner has no session) → logs scanner in as the QR owner and redirects to `redirect_url`.
**session_share** (scanner already logged in as the same user) → marks fulfilled, redirects.
**session_share** (scanner logged in as a *different* user) → redirects with `?qr_status=account_conflict`.
**login_request** (scanner logged in) → redirects to `/qr-confirm?key=…` for confirmation.
**login_request** (scanner not logged in) → redirects to `/sign-in?redirect=<scan_url>`.
""",
        responses={302: None, 404: IronErrorSerializer},
    )
    @action(detail=False, methods=["get"], url_path=r"(?P<key>[^/.]+)/scan")
    def scan(self, request, key=None):
        from urllib.parse import urlencode

        from stapel_core.django.utils import set_jwt_cookies
        from django.contrib.auth import get_user_model as _get_user_model
        from django.http import HttpResponseRedirect

        data = QRAuthService.get(key)
        if data is None:
            return IronErrorResponse(404, ERR_404_QR_NOT_FOUND)
        if data["status"] == QRStatus.FULFILLED:
            return IronErrorResponse(400, ERR_400_QR_FULFILLED)

        qr_type = data["type"]
        redirect_url = data.get("redirect_url") or "/"
        scanner = request.user if request.user.is_authenticated else None

        if qr_type == QRType.SESSION_SHARE:
            _User = _get_user_model()
            try:
                owner = _User.objects.get(pk=data["owner_user_id"])
            except _User.DoesNotExist:
                return IronErrorResponse(404, ERR_404_QR_NOT_FOUND)

            if scanner is None:
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
            _frontend = getattr(_s, 'FRONTEND_URL', 'https://app.ironmemo.com')
            from urllib.parse import urlencode as _ue
            return HttpResponseRedirect(f"{_frontend}/login?{_ue({'error': 'account_conflict'})}")

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
        responses={200: None, 404: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path=r"(?P<key>[^/.]+)/reject")
    def reject(self, request, key=None):
        data = QRAuthService.get(key)
        if data is None:
            return IronErrorResponse(404, ERR_404_QR_NOT_FOUND)
        QRAuthService.reject(key)
        from .dto import SimpleStatusResponse
        return IronResponse(SimpleStatusSerializer(SimpleStatusResponse(status='rejected')))

    @extend_schema(
        description="""Confirm a `login_request` QR code (called by the logged-in scanner after reviewing).

Issues tokens for the waiting device. The device polling `/status` will receive the tokens.
""",
        responses={
            200: None,
            400: IronErrorSerializer,
            401: IronErrorSerializer,
            404: IronErrorSerializer,
        },
    )
    @action(
        detail=False,
        methods=["post"],
        url_path=r"(?P<key>[^/.]+)/confirm",
        permission_classes=[permissions.IsAuthenticated],
    )
    def confirm(self, request, key=None):
        from stapel_core.django.jwt_provider import jwt_provider

        data = QRAuthService.get(key)
        if data is None:
            return IronErrorResponse(404, ERR_404_QR_NOT_FOUND)
        if data["status"] != QRStatus.PENDING:
            return IronErrorResponse(400, ERR_400_QR_FULFILLED)
        if data["type"] != QRType.LOGIN_REQUEST:
            return IronErrorResponse(400, ERR_400_QR_TYPE_REQUIRED)

        access_token, refresh_token = jwt_provider.create_tokens(request.user)
        QRAuthService.fulfill_login_request(
            key,
            approver_user_id=request.user.id,
            access_token=access_token,
            refresh_token=refresh_token,
        )
        from .dto import SimpleStatusResponse
        return IronResponse(SimpleStatusSerializer(SimpleStatusResponse(status='confirmed')))


# =============================================================================
# Session Management ViewSet
# =============================================================================


@extend_schema_view(
    list=extend_schema(tags=["Sessions"]),
    destroy=extend_schema(tags=["Sessions"]),
    revoke_all=extend_schema(tags=["Sessions"]),
)
class SessionViewSet(viewsets.GenericViewSet):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        description="List all active sessions for the current user.",
        responses={200: SessionResponseSerializer(many=True)},
    )
    @action(detail=False, methods=["get"], url_path="")
    def list_sessions(self, request):
        from stapel_core.django.jwt_provider import jwt_provider

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
                device_type=s.device_type or 'unknown',
                device_name=s.device_name or 'Unknown device',
                device_details=s.device_details or '',
                ip_address=s.ip_address,
                created_at=s.created_at.isoformat(),
                last_used_at=s.last_used_at.isoformat(),
                is_current=s.jti == current_jti if current_jti else False,
                is_suspicious=s.is_suspicious,
            )
            for s in sessions
        ]
        return IronResponse(SessionResponseSerializer(dtos, many=True))

    @extend_schema(
        description="Revoke a specific session by ID.",
        responses={200: None, 404: IronErrorSerializer},
    )
    @action(detail=False, methods=["delete"], url_path=r"(?P<session_id>[^/.]+)")
    def revoke_one(self, request, session_id=None):
        from .models import UserSession

        try:
            session = UserSession.objects.get(id=session_id, user=request.user)
        except UserSession.DoesNotExist:
            return IronErrorResponse(404, ERR_404_NOT_FOUND)
        session.is_revoked = True
        session.save(update_fields=["is_revoked"])
        from .services import _blacklist_jti
        _blacklist_jti(session.jti, session.expires_at)
        _blacklist_jti(session.access_jti, session.expires_at)
        from .dto import SimpleStatusResponse
        return IronResponse(SimpleStatusSerializer(SimpleStatusResponse(status='revoked')))

    @extend_schema(
        description='Mark a suspicious session as confirmed ("this was me"). Clears the suspicious flag.',
        responses={200: SimpleStatusSerializer, 404: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path=r"(?P<session_id>[^/.]+)/confirm")
    def confirm_session(self, request, session_id=None):
        from .models import UserSession
        try:
            session = UserSession.objects.get(id=session_id, user=request.user, is_revoked=False)
        except UserSession.DoesNotExist:
            return IronErrorResponse(404, ERR_404_NOT_FOUND)
        if session.is_suspicious:
            session.is_suspicious = False
            session.save(update_fields=["is_suspicious"])
        from .dto import SimpleStatusResponse
        return IronResponse(SimpleStatusSerializer(SimpleStatusResponse(status='ok')))

    @extend_schema(
        description="Revoke all sessions except the current one.",
        responses={200: None},
    )
    @action(detail=False, methods=["delete"], url_path="")
    def revoke_all(self, request):
        from stapel_core.django.jwt_provider import jwt_provider

        from .services import SessionService

        auth_header = request.META.get("HTTP_AUTHORIZATION", "")
        current_jti = None
        if auth_header.startswith("Bearer "):
            payload = (
                jwt_provider.handler.decode_token(auth_header[7:], verify=False) or {}
            )
            current_jti = payload.get("refresh_jti") or payload.get("jti")

        SessionService.revoke_all(request.user, except_jti=current_jti)
        from .dto import SimpleStatusResponse
        return IronResponse(SimpleStatusSerializer(SimpleStatusResponse(status='revoked')))


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
    def status(self, request):
        from .dto import (
            SecurityStatusContact,
            SecurityStatusOAuth,
            SecurityStatusPasskeys,
            SecurityStatusPassword,
            SecurityStatusResponse,
            SecurityStatusSessions,
            SecurityStatusTOTP,
        )
        from .models import PasskeyCredential
        from .services import SessionService, TOTPService

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

        connected_oauth = []
        if user.oauth_provider:
            connected_oauth.append(user.oauth_provider)

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
        return IronResponse(SecurityStatusResponseSerializer(dto))


# =============================================================================
# TOTP ViewSet
# =============================================================================


@extend_schema_view(
    setup=extend_schema(tags=["TOTP"]),
    confirm_setup=extend_schema(tags=["TOTP"]),
    disable=extend_schema(tags=["TOTP"]),
    challenge_verify=extend_schema(tags=["TOTP"]),
    step_up=extend_schema(tags=["TOTP"]),
)
class TOTPViewSet(viewsets.GenericViewSet):
    def get_permissions(self):
        # challenge_verify is unauthenticated (user has no token yet)
        if self.action == "challenge_verify":
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()]

    @extend_schema(
        description="Start TOTP enrollment. Returns a secret and otpauth URI for QR display.",
        request=None,
        responses={200: TOTPSetupResponseSerializer},
    )
    @action(detail=False, methods=["post"], url_path="setup")
    def setup(self, request):
        from .dto import TOTPSetupResponse
        from .services import TOTPService

        result = TOTPService.setup(request.user)
        dto = TOTPSetupResponse(
            secret=result["secret"],
            qr_uri=result["qr_uri"],
            expires_in=TOTPService.CHALLENGE_TTL,
        )
        return IronResponse(TOTPSetupResponseSerializer(dto))

    @extend_schema(
        description="Confirm TOTP setup with the first code. Activates the device and returns one-time backup codes.",
        request=TOTPSetupConfirmSerializer,
        responses={200: TOTPSetupConfirmResponseSerializer},
    )
    @action(detail=False, methods=["post"], url_path="setup/confirm")
    def confirm_setup(self, request):
        from .dto import TOTPSetupConfirmResponse
        from .services import TOTPService

        code = (request.data or {}).get("code", "")
        if not code:
            return IronErrorResponse(400, ERR_400_CODE_REQUIRED)
        try:
            plain_codes = TOTPService.confirm(request.user, str(code))
        except ValueError as e:
            if str(e) == "invalid_code":
                return IronErrorResponse(400, ERR_400_INVALID_CODE)
            return IronErrorResponse(400, ERR_400_TOTP_NOT_PENDING)
        dto = TOTPSetupConfirmResponse(backup_codes=plain_codes)
        return IronResponse(TOTPSetupConfirmResponseSerializer(dto))

    @extend_schema(
        description=(
            "Send a one-time code to the user's verified phone to confirm TOTP disable. "
            "Use when the user lost access to their authenticator and has no backup codes."
        ),
        request=None,
        responses={200: OtpSentResponseSerializer, 400: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="disable-otp/request", permission_classes=[permissions.IsAuthenticated])
    def disable_request_otp(self, request):
        from .services import PhoneVerificationService, PasswordService
        from .errors import ERR_400_NO_VERIFIED_CONTACT

        user = request.user
        if not user.phone or not user.is_phone_verified:
            return IronErrorResponse(400, ERR_400_NO_VERIFIED_CONTACT)

        PhoneVerificationService().send_verification_code(user.phone)
        from .dto import OtpSentResponse
        return IronResponse(OtpSentResponseSerializer(OtpSentResponse(
            message="Verification code sent.",
            target=PasswordService.mask_phone(user.phone),
        )))

    @extend_schema(
        description=(
            "Disable TOTP. Discriminate by `method`: "
            "`totp` → 6-digit code, `backup` → backup code, `otp` → SMS code from /totp/disable-otp/request/."
        ),
        request=TOTPDisableSerializer,
        responses={200: SimpleStatusSerializer, 400: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="disable")
    def disable(self, request):
        from .services import TOTPService, PhoneVerificationService
        from .errors import ERR_400_NO_VERIFIED_CONTACT

        data = request.data or {}
        method = data.get("method")

        if method == "totp":
            ok = TOTPService.disable(request.user, code=data.get("code"))
            if not ok:
                return IronErrorResponse(400, ERR_400_INVALID_CODE)

        elif method == "backup":
            ok = TOTPService.disable(request.user, backup_code=data.get("backup_code"))
            if not ok:
                return IronErrorResponse(400, ERR_400_INVALID_CODE)

        elif method == "otp":
            user = request.user
            if not user.phone or not user.is_phone_verified:
                return IronErrorResponse(400, ERR_400_NO_VERIFIED_CONTACT)
            result = PhoneVerificationService().verify_code(user.phone, data.get("otp_code", ""))
            if not (isinstance(result, dict) and result.get("success")):
                return IronErrorResponse(400, ERR_400_INVALID_CODE)
            TOTPService.force_disable(request.user)

        else:
            return IronErrorResponse(400, ERR_400_CODE_REQUIRED)

        AuditService.log("totp_disabled", user=request.user, request=request)
        from .dto import SimpleStatusResponse
        return IronResponse(SimpleStatusSerializer(SimpleStatusResponse(status='disabled')))

    @extend_schema(
        description="Verify TOTP challenge after password/OAuth login when TOTP is enabled. Issues JWT cookies on success.",
        request=TOTPChallengeVerifySerializer,
        responses={200: AuthResponseSerializer, 400: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="challenge/verify")
    def challenge_verify(self, request):
        from stapel_core.django.utils import set_jwt_cookies

        from .services import TOTPService

        challenge_token = (request.data or {}).get("challenge_token", "")
        code = (request.data or {}).get("code")
        backup_code = (request.data or {}).get("backup_code")

        if not challenge_token:
            return IronErrorResponse(400, ERR_400_CODE_REQUIRED)

        user = TOTPService.resolve_challenge(
            challenge_token, code=code, backup_code=backup_code
        )
        if not user:
            return IronErrorResponse(400, ERR_400_INVALID_CODE)

        access_token, refresh_token = _issue_session_tokens(user, request)
        tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
        auth_dto = AuthResponse(
            status=AuthStatus.LOGGED_IN, user=user, tokens=tokens_dto
        )
        response = IronResponse(AuthResponseSerializer(auth_dto))
        set_jwt_cookies(response, access_token, refresh_token)
        return _add_login_hints(response)

    @extend_schema(
        description="Issue a step-up token after TOTP verification. Valid for 15 minutes. Pass it as X-Step-Up-Token on sensitive actions.",
        request=TOTPStepUpSerializer,
        responses={200: TOTPStepUpResponseSerializer, 400: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="step-up")
    def step_up(self, request):
        from .dto import TOTPStepUpResponse
        from .services import TOTPService

        code = (request.data or {}).get("code", "")
        if not code:
            return IronErrorResponse(400, ERR_400_CODE_REQUIRED)
        token = TOTPService.create_step_up(request.user, str(code))
        if not token:
            return IronErrorResponse(400, ERR_400_INVALID_CODE)
        dto = TOTPStepUpResponse(
            step_up_token=token, expires_in=TOTPService.STEP_UP_TTL
        )
        return IronResponse(TOTPStepUpResponseSerializer(dto))
