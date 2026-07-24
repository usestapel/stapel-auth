"""Views for MFA (TOTP and Passkey) domain."""

import json
import logging

from drf_spectacular.utils import extend_schema
from rest_framework import permissions, viewsets
from rest_framework.decorators import action
from rest_framework.viewsets import ViewSet
from stapel_core.django.api.errors import (
    StapelErrorResponse,
    StapelResponse,
)
from stapel_core.django.openapi.schemas import StapelErrorSerializer

from stapel_auth.errors import (
    ERR_400_CODE_REQUIRED,
    ERR_400_INVALID_CODE,
    ERR_400_LAST_AUTH_METHOD,
    ERR_400_NO_VERIFIED_CONTACT,
    ERR_400_PASSKEY_CHALLENGE_EXPIRED,
    ERR_400_PASSKEY_INVALID,
    ERR_400_TOTP_NOT_ENABLED,
    ERR_400_TOTP_NOT_PENDING,
    ERR_400_TOTP_PROOF_REQUIRED,
    ERR_404_CHANGE_NOT_FOUND,
    ERR_404_PASSKEY_NOT_FOUND,
)
from stapel_auth.mfa.serializers import (
    MfaEnrollExchangeSerializer,
    MfaEnrollSessionResponseSerializer,
    PasskeyRegisterCompleteResponseSerializer,
    TOTPChallengeVerifySerializer,
    TOTPDelayedInitiateSerializer,
    TOTPDisableSerializer,
    TOTPSetupConfirmResponseSerializer,
    TOTPSetupConfirmSerializer,
    TOTPSetupRequestSerializer,
    TOTPSetupResponseSerializer,
)
from stapel_auth.otp.dto import DelayedCancelResponse, DelayedInitiateResponse, DelayedStatusResponse
from stapel_auth.otp.serializers import (
    DelayedCancelResponseSerializer,
    DelayedChangeCancelSerializer,
    DelayedInitiateResponseSerializer,
    DelayedStatusResponseSerializer,
    OtpSentResponseSerializer,
)
from stapel_auth.sessions.serializers import (
    AuthResponseSerializer,
    SimpleStatusSerializer,
)
from stapel_auth.utils import SerializerSeamsMixin
from stapel_auth.permissions import DenyEnrollOnly, is_enroll_only_request

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
    options = _serializers.DictField()


class _PasskeyRegisterCompleteBodySerializer(_serializers.Serializer):
    credential = _serializers.JSONField()
    device_name = _serializers.CharField(required=False, default="", allow_blank=True)


class _PasskeyAuthBeginBodySerializer(_serializers.Serializer):
    email = _serializers.EmailField(required=False, allow_null=True, default=None)


class _PasskeyAuthCompleteBodySerializer(_serializers.Serializer):
    session_key = _serializers.CharField()
    credential = _serializers.JSONField()


def _pc_to_dict(pc):
    return {
        "id": str(pc.id),
        "device_name": pc.device_name,
        "aaguid": pc.aaguid,
        "transports": pc.transports or [],
        "created_at": pc.created_at,
        "last_used_at": pc.last_used_at,
    }


# =============================================================================
# TOTPViewSet
# =============================================================================


class TOTPViewSet(SerializerSeamsMixin, viewsets.GenericViewSet):
    # Overridable serializer seams (see SerializerSeamsMixin).
    setup_response_serializer_class = TOTPSetupResponseSerializer
    confirm_setup_response_serializer_class = TOTPSetupConfirmResponseSerializer
    otp_sent_response_serializer_class = OtpSentResponseSerializer
    status_response_serializer_class = SimpleStatusSerializer
    auth_response_serializer_class = AuthResponseSerializer
    delayed_initiate_response_serializer_class = DelayedInitiateResponseSerializer
    delayed_status_response_serializer_class = DelayedStatusResponseSerializer
    delayed_cancel_response_serializer_class = DelayedCancelResponseSerializer

    def get_permissions(self):
        # challenge_verify is unauthenticated (user has no token yet).
        # DenyEnrollOnly lets an enroll-only session reach setup/confirm_setup
        # (central allowlist in permissions.py) and 403s the rest.
        if self.action == "challenge_verify":
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated(), DenyEnrollOnly()]

    @extend_schema(
        description=(
            "Start TOTP enrollment. Returns a secret and otpauth URI for QR display. "
            "If TOTP is already enabled (replacing an existing device), `code` or "
            "`backup_code` proving the CURRENT device is required — otherwise this "
            "returns 400 `totp_proof_required`. Lost the current device entirely? "
            "Use `/totp/change/delayed/initiate/` instead."
        ),
        request=TOTPSetupRequestSerializer,
        responses={200: TOTPSetupResponseSerializer, 400: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="setup")
    def setup(self, request):  # noqa: R007
        from stapel_auth.mfa.dto import TOTPSetupResponse
        from stapel_auth.mfa.services import TOTPService

        data = request.data or {}
        try:
            result = TOTPService.setup(
                request.user,
                code=data.get("code") or None,
                backup_code=data.get("backup_code") or None,
            )
        except ValueError:
            return StapelErrorResponse(400, ERR_400_TOTP_PROOF_REQUIRED)
        dto = TOTPSetupResponse(
            secret=result["secret"],
            qr_uri=result["qr_uri"],
            expires_in=TOTPService.CHALLENGE_TTL,
        )
        return StapelResponse(self.get_setup_response_serializer_class()(dto))

    @extend_schema(
        description=(
            "Confirm TOTP setup with the first code. Activates the device and "
            "returns one-time backup codes. When called from a limited "
            "enroll-only session (first-login mfa_enroll policy), activating "
            "the strong factor clears the enrollment flag and the response "
            "additionally carries a full-session token pair (`tokens`) — the "
            "limited session is upgraded on the spot."
        ),
        request=TOTPSetupConfirmSerializer,
        responses={200: TOTPSetupConfirmResponseSerializer},
    )
    @action(detail=False, methods=["post"], url_path="setup/confirm")
    def confirm_setup(self, request):  # noqa: R007
        from stapel_auth.mfa.dto import TOTPSetupConfirmResponse
        from stapel_auth.mfa.services import TOTPService, notify_totp_change
        from stapel_auth.sessions.services import AuditService

        code = (request.data or {}).get("code", "")
        if not code:
            return StapelErrorResponse(400, ERR_400_CODE_REQUIRED)
        try:
            # The service clears mfa_enrollment_required and writes the
            # user.mfa_enabled outbox transition atomically with activation.
            plain_codes = TOTPService.confirm(request.user, str(code))
        except ValueError as e:
            if str(e) == "invalid_code":
                return StapelErrorResponse(400, ERR_400_INVALID_CODE)
            return StapelErrorResponse(400, ERR_400_TOTP_NOT_PENDING)

        AuditService.log("totp_enabled", user=request.user, request=request)
        notify_totp_change(request.user, "totp_enabled")

        dto = TOTPSetupConfirmResponse(backup_codes=plain_codes)

        if is_enroll_only_request(request):
            # Enroll-only upgrade (org-program §C2): the strong factor is
            # live — mint the full session the login withheld.
            from stapel_core.django.jwt.utils import set_jwt_cookies

            from stapel_auth.hint_cookie import set_auth_hint_cookie
            from stapel_auth.sessions.dto import TokenPairResponse
            from stapel_auth.sessions.views import _issue_session_tokens

            access_token, refresh_token = _issue_session_tokens(request.user, request)
            dto.tokens = TokenPairResponse(refresh=refresh_token, access=access_token)
            response = StapelResponse(
                self.get_confirm_setup_response_serializer_class()(dto)
            )
            set_jwt_cookies(response, access_token, refresh_token)
            set_auth_hint_cookie(response)
            return response

        return StapelResponse(self.get_confirm_setup_response_serializer_class()(dto))

    @extend_schema(
        description=(
            "Send a one-time code to the user's verified phone to confirm TOTP disable. "
            "Use when the user lost access to their authenticator and has no backup codes."
        ),
        request=None,
        responses={200: None, 400: StapelErrorSerializer},
    )
    @action(
        detail=False,
        methods=["post"],
        url_path="disable-otp/request",
        permission_classes=[permissions.IsAuthenticated],
    )
    def disable_request_otp(self, request):  # noqa: R007
        from stapel_auth.otp.dto import OtpSentResponse
        from stapel_auth.errors import ERR_400_NO_VERIFIED_CONTACT
        from stapel_auth.otp.services import PhoneVerificationService
        from stapel_auth.password.services import PasswordService

        user = request.user
        if not user.phone or not user.is_phone_verified:
            return StapelErrorResponse(400, ERR_400_NO_VERIFIED_CONTACT)

        PhoneVerificationService().send_verification_code(user.phone)
        return StapelResponse(
            self.get_otp_sent_response_serializer_class()(
                OtpSentResponse(
                    message="Verification code sent.",
                    target=PasswordService.mask_phone(user.phone),
                )
            )
        )

    @extend_schema(
        description=(
            "Disable TOTP. Discriminate by `method`: "
            "`totp` → 6-digit code, `backup` → backup code, `otp` → SMS code from /totp/disable-otp/request/."
        ),
        request=TOTPDisableSerializer,
        responses={200: None, 400: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="disable")
    def disable(self, request):  # noqa: R007
        from stapel_auth.dto import SimpleStatusResponse
        from stapel_auth.errors import ERR_400_NO_VERIFIED_CONTACT
        from stapel_auth.mfa.services import TOTPService, notify_totp_change
        from stapel_auth.otp.services import PhoneVerificationService
        from stapel_auth.sessions.services import AuditService

        data = request.data or {}
        method = data.get("method")

        if method == "totp":
            ok = TOTPService.disable(request.user, code=data.get("code"))
            if not ok:
                return StapelErrorResponse(400, ERR_400_INVALID_CODE)

        elif method == "backup":
            ok = TOTPService.disable(request.user, backup_code=data.get("backup_code"))
            if not ok:
                return StapelErrorResponse(400, ERR_400_INVALID_CODE)

        elif method == "otp":
            user = request.user
            if not user.phone or not user.is_phone_verified:
                return StapelErrorResponse(400, ERR_400_NO_VERIFIED_CONTACT)
            result = PhoneVerificationService().verify_code(
                user.phone, data.get("otp_code", "")
            )
            if not (isinstance(result, dict) and result.get("success")):
                return StapelErrorResponse(400, ERR_400_INVALID_CODE)
            TOTPService.force_disable(request.user)

        else:
            return StapelErrorResponse(400, ERR_400_CODE_REQUIRED)

        AuditService.log("totp_disabled", user=request.user, request=request)
        notify_totp_change(request.user, "totp_disabled")
        return StapelResponse(
            self.get_status_response_serializer_class()(
                SimpleStatusResponse(status="disabled")
            )
        )

    @extend_schema(
        description="Verify TOTP challenge after password/OAuth login when TOTP is enabled. Issues JWT cookies on success.",
        request=TOTPChallengeVerifySerializer,
        responses={200: None, 400: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="challenge/verify")
    def challenge_verify(self, request):  # noqa: R007
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from stapel_auth.hint_cookie import set_auth_hint_cookie
        from stapel_auth.sessions.dto import AuthResponse, AuthStatus, TokenPairResponse
        from stapel_auth.mfa.services import TOTPService
        from stapel_auth.sessions.views import _add_login_hints, _issue_session_tokens

        challenge_token = (request.data or {}).get("challenge_token", "")
        code = (request.data or {}).get("code")
        backup_code = (request.data or {}).get("backup_code")

        if not challenge_token:
            return StapelErrorResponse(400, ERR_400_CODE_REQUIRED)

        # Throttle TOTP guessing with the same LockoutService pattern used
        # for password login. Keyed per challenge token — the token is the
        # only stable identifier an unauthenticated caller presents.
        from stapel_auth.errors import ERR_423_ACCOUNT_LOCKED, retry_params
        from stapel_auth.security.services import LockoutService

        lock_id = f"totp_challenge:{challenge_token}"
        is_locked, retry_after = LockoutService.check(lock_id)
        if is_locked:
            return StapelErrorResponse(
                423, ERR_423_ACCOUNT_LOCKED, params=retry_params(retry_after)
            )

        user = TOTPService.resolve_challenge(
            challenge_token, code=code, backup_code=backup_code
        )
        if not user:
            count = LockoutService.record_failure(lock_id)
            duration = LockoutService.apply_lockout(lock_id, count, request=request)
            if duration:
                return StapelErrorResponse(
                    423, ERR_423_ACCOUNT_LOCKED, params=retry_params(duration)
                )
            return StapelErrorResponse(400, ERR_400_INVALID_CODE)

        LockoutService.clear(lock_id)

        # First-login policy (org-program §C2): a flagged account that just
        # proved its TOTP still gets the first-login intermediate, not a
        # session — same check password login runs for TOTP-less accounts.
        from stapel_auth.password.views import first_login_intermediate_response

        intermediate = first_login_intermediate_response(user)
        if intermediate is not None:
            return intermediate

        access_token, refresh_token = _issue_session_tokens(user, request)
        tokens_dto = TokenPairResponse(refresh=refresh_token, access=access_token)
        auth_dto = AuthResponse(
            status=AuthStatus.LOGGED_IN, user=user, tokens=tokens_dto
        )
        response = StapelResponse(self.get_auth_response_serializer_class()(auth_dto))
        set_jwt_cookies(response, access_token, refresh_token)
        set_auth_hint_cookie(response)
        return _add_login_hints(response)

    # ── Delayed change (lost device — no code/backup code available) ────────
    #
    # Mirrors the phone/email delayed authenticator-change flow (otp.views.
    # AuthenticatorChangeViewSet) end to end: same AuthenticatorChangeRequest
    # model/status machine, same DELAYED_PERIOD_DAYS cooldown, same day-1/7/13
    # notifications + cancel window (tasks.send_change_notifications /
    # execute_pending_changes / cleanup_expired_requests). The only
    # difference is what gets applied at the end — a TOTP disable, not a
    # contact swap (see AuthenticatorChangeService.initiate_delayed_totp).

    def _totp_change_error_response(self, result):
        error = result.get("error", "unknown_error")
        if error == "not_enabled":
            return StapelErrorResponse(400, ERR_400_TOTP_NOT_ENABLED)
        if error == "no_verified_contact":
            return StapelErrorResponse(400, ERR_400_NO_VERIFIED_CONTACT)
        if error == "not_found":
            return StapelErrorResponse(404, ERR_404_CHANGE_NOT_FOUND)
        return StapelErrorResponse(400, ERR_400_CODE_REQUIRED)

    @extend_schema(
        description=(
            "Request a delayed TOTP removal — for when the current device is "
            "LOST (no code or backup code available), so the instant "
            "`/totp/setup/` (replace) or `/totp/disable/` proof-gated paths "
            "can't be used. Requires a verified email or phone: it is "
            "notified on day 1/7/13 of the cooldown and can cancel the "
            "request at any point before it applies. No verified contact on "
            "the account -> 400 `no_verified_contact` (a support case, not "
            "a self-serve path)."
        ),
        request=TOTPDelayedInitiateSerializer,
        responses={201: DelayedInitiateResponseSerializer, 400: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="change/delayed/initiate")
    def delayed_initiate(self, request):  # noqa: R007
        from rest_framework import status as drf_status

        from stapel_auth.otp.services import AuthenticatorChangeService

        serializer = TOTPDelayedInitiateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        ip = request.headers.get("x-forwarded-for", request.META.get("REMOTE_ADDR", ""))
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()

        svc = AuthenticatorChangeService()
        result = svc.initiate_delayed_totp(
            request.user,
            device_id=serializer.validated_data.get("device_id", ""),
            ip=ip or None,
            user_agent=request.headers.get("user-agent", ""),
        )
        if result.get("success"):
            dto = DelayedInitiateResponse(
                status="PENDING",
                change_request_id=result["change_request_id"],
                new_value_masked="authenticator app",
                scheduled_at=result["scheduled_at"],
                can_cancel_until=result["scheduled_at"],
            )
            return StapelResponse(
                self.get_delayed_initiate_response_serializer_class()(dto),
                status=drf_status.HTTP_201_CREATED,
            )
        return self._totp_change_error_response(result)

    @extend_schema(
        description="Status of a pending delayed TOTP removal, if any.",
        responses={200: DelayedStatusResponseSerializer},
    )
    @action(detail=False, methods=["get"], url_path="change/delayed/status")
    def delayed_status(self, request):  # noqa: R007
        from stapel_auth.otp.services import AuthenticatorChangeService

        svc = AuthenticatorChangeService()
        info = svc.get_pending_status(request.user, "totp")
        if info:
            dto = DelayedStatusResponse(has_pending_change=True, **info)
        else:
            dto = DelayedStatusResponse(has_pending_change=False)
        return StapelResponse(self.get_delayed_status_response_serializer_class()(dto))

    @extend_schema(
        description="Cancel a pending delayed TOTP removal.",
        request=DelayedChangeCancelSerializer,
        responses={200: DelayedCancelResponseSerializer, 404: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="change/delayed/cancel")
    def delayed_cancel(self, request):  # noqa: R007
        from stapel_auth.otp.services import AuthenticatorChangeService

        serializer = DelayedChangeCancelSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        svc = AuthenticatorChangeService()
        result = svc.cancel_pending(
            request.user, "totp", serializer.validated_data["change_request_id"]
        )
        if result.get("success"):
            dto = DelayedCancelResponse(
                status="CANCELLED", message="TOTP change request cancelled"
            )
            return StapelResponse(self.get_delayed_cancel_response_serializer_class()(dto))
        return self._totp_change_error_response(result)


# =============================================================================
# PasskeyViewSet
# =============================================================================


@extend_schema(tags=["Passkeys"])
class PasskeyViewSet(SerializerSeamsMixin, ViewSet):
    # Overridable serializer seams (see SerializerSeamsMixin).
    list_response_serializer_class = _PasskeyListResponseSerializer
    register_begin_response_serializer_class = _PasskeyRegOptionsSerializer
    register_complete_request_serializer_class = _PasskeyRegisterCompleteBodySerializer
    register_complete_response_serializer_class = PasskeyRegisterCompleteResponseSerializer
    auth_begin_request_serializer_class = _PasskeyAuthBeginBodySerializer
    auth_begin_response_serializer_class = _PasskeyAuthOptionsSerializer
    auth_complete_request_serializer_class = _PasskeyAuthCompleteBodySerializer
    auth_response_serializer_class = AuthResponseSerializer

    _anon_actions = frozenset({"auth_begin", "auth_complete"})

    def get_permissions(self):
        # DenyEnrollOnly lets an enroll-only session register a passkey
        # (central allowlist in permissions.py) and 403s list/destroy.
        if self.action in self._anon_actions:
            return [permissions.AllowAny()]
        return [permissions.IsAuthenticated(), DenyEnrollOnly()]

    @extend_schema(
        summary="List registered passkeys",
        responses={200: _PasskeyListResponseSerializer},
    )
    def get_list(self, request):
        from stapel_auth.models import PasskeyCredential

        qs = PasskeyCredential.objects.filter(
            user=request.user, is_active=True
        ).order_by("-created_at")
        data = [_pc_to_dict(pc) for pc in qs]
        return StapelResponse(
            self.get_list_response_serializer_class()({"passkeys": data})
        )

    @extend_schema(summary="Remove a passkey", responses={204: None})
    def destroy(self, request, pk=None):
        from stapel_auth.models import PasskeyCredential

        try:
            pc = PasskeyCredential.objects.get(id=pk, user=request.user, is_active=True)
        except PasskeyCredential.DoesNotExist:
            return StapelErrorResponse(404, ERR_404_PASSKEY_NOT_FOUND)

        # Require at least one other auth method
        user = request.user
        has_password = bool(
            getattr(user, "password", None) and user.password not in ("", "!")
        )
        has_totp = getattr(user, "totp_enabled", False)
        other_passkeys = (
            PasskeyCredential.objects.filter(user=user, is_active=True)
            .exclude(id=pk)
            .exists()
        )
        if not (has_password or has_totp or other_passkeys):
            return StapelErrorResponse(400, ERR_400_LAST_AUTH_METHOD)

        # Deactivate through the service so the user.mfa_disabled outbox
        # transition (last strong factor gone, org-program §C3) commits
        # atomically with the flip.
        from stapel_auth.mfa.services import PasskeyService

        PasskeyService.deactivate(user, pc)
        from stapel_auth.sessions.services import AuditService

        AuditService.log("passkey_removed", user=user, device_name=pc.device_name)
        return StapelResponse(status=204)

    @extend_schema(
        summary="Begin passkey registration (generate options)",
        request=None,
        responses={200: _PasskeyRegOptionsSerializer, 400: StapelErrorSerializer},
    )
    def register_begin(self, request):
        from stapel_auth.mfa.services import PasskeyService

        try:
            options_json = PasskeyService.registration_begin(request.user)
        except Exception:
            logger.exception("passkey register_begin failed")
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)
        options = (
            json.loads(options_json) if isinstance(options_json, str) else options_json
        )
        return StapelResponse(
            self.get_register_begin_response_serializer_class()({"options": options})
        )

    @extend_schema(
        summary="Complete passkey registration",
        description=(
            "Verify the WebAuthn attestation and store the credential. When "
            "called from a limited enroll-only session (first-login "
            "mfa_enroll policy), activating the strong factor clears the "
            "enrollment flag and the response additionally carries a "
            "full-session token pair (`tokens`)."
        ),
        request=_PasskeyRegisterCompleteBodySerializer,
        responses={200: PasskeyRegisterCompleteResponseSerializer},
    )
    def register_complete(self, request):
        from stapel_auth.mfa.services import PasskeyService

        ser = self.get_register_complete_request_serializer_class()(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            # The service clears mfa_enrollment_required and writes the
            # user.mfa_enabled outbox transition atomically with the create.
            pc = PasskeyService.registration_complete(
                request.user,
                ser.validated_data["credential"],
                device_name=ser.validated_data.get("device_name", ""),
            )
        except ValueError as exc:
            code = str(exc)
            if code == "challenge_expired":
                return StapelErrorResponse(400, ERR_400_PASSKEY_CHALLENGE_EXPIRED)
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)
        except Exception:
            logger.exception("passkey register_complete failed")
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)

        data = _pc_to_dict(pc)

        if is_enroll_only_request(request):
            # Enroll-only upgrade (org-program §C2): mint the full session
            # the login withheld.
            from stapel_core.django.jwt.utils import set_jwt_cookies

            from stapel_auth.hint_cookie import set_auth_hint_cookie
            from stapel_auth.sessions.views import _issue_session_tokens

            access_token, refresh_token = _issue_session_tokens(request.user, request)
            data["tokens"] = {"access": access_token, "refresh": refresh_token}
            response = StapelResponse(
                self.get_register_complete_response_serializer_class()(data)
            )
            set_jwt_cookies(response, access_token, refresh_token)
            set_auth_hint_cookie(response)
            return response

        return StapelResponse(
            self.get_register_complete_response_serializer_class()(data)
        )

    @extend_schema(
        summary="Begin passkey authentication",
        request=_PasskeyAuthBeginBodySerializer,
        responses={200: _PasskeyAuthOptionsSerializer},
    )
    def auth_begin(self, request):
        from stapel_auth.mfa.services import PasskeyService

        ser = self.get_auth_begin_request_serializer_class()(data=request.data)
        ser.is_valid(raise_exception=True)
        user = None
        email = ser.validated_data.get("email")
        if email:
            from django.contrib.auth import get_user_model

            U = get_user_model()
            try:
                user = U.objects.get(email=email, is_active=True)
            except U.DoesNotExist:
                pass
        try:
            session_key, options_json = PasskeyService.authentication_begin(user)
        except Exception:
            logger.exception("passkey auth_begin failed")
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)
        options = (
            json.loads(options_json) if isinstance(options_json, str) else options_json
        )
        return StapelResponse(
            self.get_auth_begin_response_serializer_class()(
                {"session_key": session_key, "options": options}
            )
        )

    @extend_schema(
        summary="Complete passkey authentication and issue session",
        request=_PasskeyAuthCompleteBodySerializer,
        responses={200: None},
    )
    def auth_complete(self, request):
        from stapel_auth.mfa.services import PasskeyService
        from stapel_auth.sessions.views import _add_login_hints, _issue_session_tokens

        ser = self.get_auth_complete_request_serializer_class()(data=request.data)
        ser.is_valid(raise_exception=True)
        try:
            user, pc = PasskeyService.authentication_complete(
                ser.validated_data["session_key"],
                ser.validated_data["credential"],
            )
        except ValueError as exc:
            code = str(exc)
            if code == "challenge_expired":
                return StapelErrorResponse(400, ERR_400_PASSKEY_CHALLENGE_EXPIRED)
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)
        except Exception:
            logger.exception("passkey auth_complete failed")
            return StapelErrorResponse(400, ERR_400_PASSKEY_INVALID)

        access_token, refresh_token = _issue_session_tokens(user, request)
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from stapel_auth.hint_cookie import set_auth_hint_cookie
        from stapel_auth.sessions.dto import AuthResponse, AuthStatus, TokenPairResponse

        dto = AuthResponse(
            status=AuthStatus.LOGGED_IN,
            user=user,
            tokens=TokenPairResponse(refresh=refresh_token, access=access_token),
        )
        response = StapelResponse(self.get_auth_response_serializer_class()(dto))
        set_jwt_cookies(response, access_token, refresh_token)
        set_auth_hint_cookie(response)
        return _add_login_hints(response)


# =============================================================================
# MfaEnrollViewSet — first-login mfa_enroll exchange (org-program §C2)
# =============================================================================


class MfaEnrollViewSet(SerializerSeamsMixin, viewsets.GenericViewSet):
    """Exchange a first-login mfa_enroll challenge for a LIMITED session.

    The limited session is an access token carrying the ``enroll_only`` JWT
    claim — deliberately with NO refresh token (a refresh would mint a
    claim-free access token and silently escalate the session) and no
    UserSession row (nothing to revoke; it just expires). While it lives,
    :class:`stapel_auth.permissions.DenyEnrollOnly` cuts the API surface
    down to TOTP setup/confirm, passkey registration and logout; activating
    a strong factor upgrades to a full session in the confirm response.
    """

    permission_classes = [permissions.AllowAny]

    # Overridable serializer seams (see SerializerSeamsMixin).
    exchange_request_serializer_class = MfaEnrollExchangeSerializer
    enroll_session_response_serializer_class = MfaEnrollSessionResponseSerializer

    @extend_schema(
        tags=["MFA Enroll"],
        description=(
            "Exchange the first-login challenge_token (requires=mfa_enroll) "
            "for a limited enroll-only session. The returned access token "
            "carries the `enroll_only` claim and only allows TOTP "
            "setup/confirm, passkey registration and logout; activating a "
            "strong factor clears the enrollment flag and returns a full "
            "session from the confirm endpoint. Single-use; 400 "
            "`first_login_challenge_invalid` on an unknown/expired token."
        ),
        request=MfaEnrollExchangeSerializer,
        responses={200: MfaEnrollSessionResponseSerializer, 400: StapelErrorSerializer},
    )
    @action(detail=False, methods=["post"], url_path="enroll/exchange")
    def exchange(self, request):  # noqa: R007
        from stapel_core.django.jwt.provider import jwt_provider
        from stapel_core.django.jwt.utils import set_jwt_cookies

        from stapel_auth.errors import ERR_400_FIRST_LOGIN_CHALLENGE_INVALID
        from stapel_auth.mfa.dto import (
            MfaEnrollSessionResponse,
            MfaEnrollSessionStatus,
        )
        from stapel_auth.password.services import FirstLoginPolicyService
        from stapel_auth.sessions.services import AuditService
        from stapel_auth.staff_roles import serialize_user_to_jwt_data

        ser = self.get_exchange_request_serializer_class()(data=request.data)
        ser.is_valid(raise_exception=True)
        token = ser.validated_data["challenge_token"]

        user = FirstLoginPolicyService.resolve_challenge(
            token, FirstLoginPolicyService.REQUIRES_MFA_ENROLL
        )
        if user is None:
            return StapelErrorResponse(400, ERR_400_FIRST_LOGIN_CHALLENGE_INVALID)
        FirstLoginPolicyService.burn_challenge(token)

        data = serialize_user_to_jwt_data(user)
        data["enroll_only"] = True
        access_token = jwt_provider.manager.create_access_token(data)
        expires_in = int(jwt_provider.config.access_token_lifetime.total_seconds())

        AuditService.log("mfa_enroll_session", user=user, request=request)

        dto = MfaEnrollSessionResponse(
            status=MfaEnrollSessionStatus.MFA_ENROLL_SESSION,
            access=access_token,
            expires_in=expires_in,
        )
        response = StapelResponse(
            self.get_enroll_session_response_serializer_class()(dto)
        )
        # Access cookie only — no refresh cookie for a limited session.
        set_jwt_cookies(response, access_token)
        return response
