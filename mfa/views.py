"""Views for MFA (TOTP and Passkey) domain."""
import json
import logging

from drf_spectacular.utils import extend_schema
from rest_framework import permissions, viewsets
from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet

from stapel_core.django.api.errors import (
    ERR_400_BAD_REQUEST,
    IronErrorResponse,
    IronResponse,
)

from stapel_auth.errors import (
    ERR_400_CODE_REQUIRED,
    ERR_400_INVALID_CODE,
    ERR_400_TOTP_NOT_PENDING,
    ERR_400_PASSKEY_INVALID,
    ERR_400_PASSKEY_CHALLENGE_EXPIRED,
    ERR_400_LAST_AUTH_METHOD,
    ERR_404_PASSKEY_NOT_FOUND,
)
from stapel_auth.mfa.serializers import (
    TOTPChallengeVerifySerializer,
    TOTPSetupConfirmSerializer,
    TOTPDisableSerializer,
    TOTPSetupResponseSerializer,
    TOTPSetupConfirmResponseSerializer,
    TOTPStepUpSerializer,
    TOTPStepUpResponseSerializer,
    PasskeyItemSerializer,
)

from stapel_core.django.openapi.schemas import IronErrorSerializer

logger = logging.getLogger(__name__)


# ── Inline serializers for passkey list/reg/auth (kept here as in original) ──

from rest_framework import serializers as _serializers


class _PasskeyListResponseSerializer(_serializers.Serializer):
    from stapel_auth.mfa.serializers import PasskeyItemSerializer as _PIS
    passkeys = _PIS(many=True)


class _PasskeyRegOptionsSerializer(_serializers.Serializer):
    options = _serializers.DictField()


class _PasskeyAuthOptionsSerializer(_serializers.Serializer):
    session_key = _serializers.CharField()
    options     = _serializers.DictField()


class _PasskeyRegisterCompleteBodySerializer(_serializers.Serializer):
    credential  = _serializers.JSONField()
    device_name = _serializers.CharField(required=False, default='', allow_blank=True)


class _PasskeyAuthBeginBodySerializer(_serializers.Serializer):
    email = _serializers.EmailField(required=False, allow_null=True, default=None)


class _PasskeyAuthCompleteBodySerializer(_serializers.Serializer):
    session_key = _serializers.CharField()
    credential  = _serializers.JSONField()


def _pc_to_dict(pc):
    return {
        'id': str(pc.id),
        'device_name': pc.device_name,
        'aaguid': pc.aaguid,
        'transports': pc.transports or [],
        'created_at': pc.created_at,
        'last_used_at': pc.last_used_at,
    }


# =============================================================================
# TOTPViewSet
# =============================================================================

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
        from stapel_auth.mfa.dto import TOTPSetupResponse
        from stapel_auth.mfa.services import TOTPService

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
        from stapel_auth.mfa.dto import TOTPSetupConfirmResponse
        from stapel_auth.mfa.services import TOTPService

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
        responses={200: None, 400: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="disable-otp/request", permission_classes=[permissions.IsAuthenticated])
    def disable_request_otp(self, request):
        from stapel_auth.services import PhoneVerificationService, PasswordService
        from stapel_auth.errors import ERR_400_NO_VERIFIED_CONTACT
        from stapel_auth.dto import OtpSentResponse
        from stapel_auth.serializers import OtpSentResponseSerializer

        user = request.user
        if not user.phone or not user.is_phone_verified:
            return IronErrorResponse(400, ERR_400_NO_VERIFIED_CONTACT)

        PhoneVerificationService().send_verification_code(user.phone)
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
        responses={200: None, 400: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="disable")
    def disable(self, request):
        from stapel_auth.mfa.services import TOTPService
        from stapel_auth.services import PhoneVerificationService, AuditService
        from stapel_auth.errors import ERR_400_NO_VERIFIED_CONTACT
        from stapel_auth.dto import SimpleStatusResponse
        from stapel_auth.serializers import SimpleStatusSerializer

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
        return IronResponse(SimpleStatusSerializer(SimpleStatusResponse(status='disabled')))

    @extend_schema(
        description="Verify TOTP challenge after password/OAuth login when TOTP is enabled. Issues JWT cookies on success.",
        request=TOTPChallengeVerifySerializer,
        responses={200: None, 400: IronErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="challenge/verify")
    def challenge_verify(self, request):
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from stapel_auth.mfa.services import TOTPService
        from stapel_auth.sessions.views import _issue_session_tokens, _add_login_hints
        from stapel_auth.dto import TokenPairResponse, AuthResponse, AuthStatus
        from stapel_auth.serializers import AuthResponseSerializer

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
        from stapel_auth.mfa.dto import TOTPStepUpResponse
        from stapel_auth.mfa.services import TOTPService

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


# =============================================================================
# PasskeyViewSet
# =============================================================================

@extend_schema(tags=['Passkeys'])
class PasskeyViewSet(ViewSet):
    _anon_actions = frozenset({'auth_begin', 'auth_complete'})

    def get_permissions(self):
        if self.action in self._anon_actions:
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated()]

    @extend_schema(summary='List registered passkeys', responses={200: _PasskeyListResponseSerializer})
    def get_list(self, request):
        from stapel_auth.models import PasskeyCredential
        qs = PasskeyCredential.objects.filter(user=request.user, is_active=True).order_by('-created_at')
        data = [_pc_to_dict(pc) for pc in qs]
        return IronResponse(_PasskeyListResponseSerializer({'passkeys': data}))

    @extend_schema(summary='Remove a passkey', responses={204: None})
    def destroy(self, request, pk=None):
        from stapel_auth.models import PasskeyCredential
        try:
            pc = PasskeyCredential.objects.get(id=pk, user=request.user, is_active=True)
        except PasskeyCredential.DoesNotExist:
            return IronErrorResponse(404, ERR_404_PASSKEY_NOT_FOUND)

        # Require at least one other auth method
        user = request.user
        has_password = bool(getattr(user, 'password', None) and user.password not in ('', '!'))
        has_totp     = getattr(user, 'totp_enabled', False)
        other_passkeys = PasskeyCredential.objects.filter(user=user, is_active=True).exclude(id=pk).exists()
        if not (has_password or has_totp or other_passkeys):
            return IronErrorResponse(400, ERR_400_LAST_AUTH_METHOD)

        pc.is_active = False
        pc.save(update_fields=['is_active'])
        from stapel_auth.services import AuditService
        AuditService.log('passkey_removed', user=user, device_name=pc.device_name)
        return IronResponse(status=204)

    @extend_schema(
        summary='Begin passkey registration (generate options)',
        responses={200: _PasskeyRegOptionsSerializer},
    )
    def register_begin(self, request):
        from stapel_auth.mfa.services import PasskeyService
        try:
            options_json = PasskeyService.registration_begin(request.user)
        except Exception:
            logger.exception('passkey register_begin failed')
            return IronErrorResponse(400, ERR_400_PASSKEY_INVALID)
        options = json.loads(options_json) if isinstance(options_json, str) else options_json
        return IronResponse(_PasskeyRegOptionsSerializer({'options': options}))

    @extend_schema(
        summary='Complete passkey registration',
        request=_PasskeyRegisterCompleteBodySerializer,
        responses={200: PasskeyItemSerializer},
    )
    def register_complete(self, request):
        from stapel_auth.mfa.services import PasskeyService
        ser = _PasskeyRegisterCompleteBodySerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            pc = PasskeyService.registration_complete(
                request.user,
                ser.validated_data['credential'],
                device_name=ser.validated_data.get('device_name', ''),
            )
        except ValueError as exc:
            code = str(exc)
            if code == 'challenge_expired':
                return IronErrorResponse(400, ERR_400_PASSKEY_CHALLENGE_EXPIRED)
            return IronErrorResponse(400, ERR_400_PASSKEY_INVALID)
        except Exception:
            logger.exception('passkey register_complete failed')
            return IronErrorResponse(400, ERR_400_PASSKEY_INVALID)
        return IronResponse(PasskeyItemSerializer(_pc_to_dict(pc)))

    @extend_schema(
        summary='Begin passkey authentication',
        request=_PasskeyAuthBeginBodySerializer,
        responses={200: _PasskeyAuthOptionsSerializer},
    )
    def auth_begin(self, request):
        from stapel_auth.mfa.services import PasskeyService
        ser = _PasskeyAuthBeginBodySerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        user = None
        email = ser.validated_data.get('email')
        if email:
            from stapel_core.django.users.models import User as U
            try:
                user = U.objects.get(email=email, is_active=True)
            except U.DoesNotExist:
                pass
        try:
            session_key, options_json = PasskeyService.authentication_begin(user)
        except Exception:
            logger.exception('passkey auth_begin failed')
            return IronErrorResponse(400, ERR_400_PASSKEY_INVALID)
        options = json.loads(options_json) if isinstance(options_json, str) else options_json
        return IronResponse(_PasskeyAuthOptionsSerializer({'session_key': session_key, 'options': options}))

    @extend_schema(
        summary='Complete passkey authentication and issue session',
        request=_PasskeyAuthCompleteBodySerializer,
        responses={200: None},
    )
    def auth_complete(self, request):
        from stapel_auth.mfa.services import PasskeyService
        from stapel_auth.sessions.views import _issue_session_tokens, _add_login_hints
        ser = _PasskeyAuthCompleteBodySerializer(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            user, pc = PasskeyService.authentication_complete(
                ser.validated_data['session_key'],
                ser.validated_data['credential'],
            )
        except ValueError as exc:
            code = str(exc)
            if code == 'challenge_expired':
                return IronErrorResponse(400, ERR_400_PASSKEY_CHALLENGE_EXPIRED)
            return IronErrorResponse(400, ERR_400_PASSKEY_INVALID)
        except Exception:
            logger.exception('passkey auth_complete failed')
            return IronErrorResponse(400, ERR_400_PASSKEY_INVALID)

        access_token, refresh_token = _issue_session_tokens(user, request)
        from stapel_core.django.jwt.utils import set_jwt_cookies
        from stapel_auth.dto import AuthResponse, AuthStatus, TokenPairResponse
        from stapel_auth.serializers import AuthResponseSerializer
        dto = AuthResponse(
            status=AuthStatus.LOGGED_IN,
            user=user,
            tokens=TokenPairResponse(refresh=refresh_token, access=access_token),
        )
        response = IronResponse(AuthResponseSerializer(dto))
        set_jwt_cookies(response, access_token, refresh_token)
        return _add_login_hints(response)
