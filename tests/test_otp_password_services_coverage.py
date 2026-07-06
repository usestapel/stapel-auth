"""
Coverage tests for the OTP + password service/serializer layer.

Targets the missing branches in:
  - stapel_auth.otp.services      (AuthenticatorChangeService flows, helpers)
  - stapel_auth.otp.serializers   (validation branches)
  - stapel_auth.password.services (PasswordService reset/change/set flows)
  - stapel_auth.password.serializers (validation branches)

Views are intentionally NOT exercised here (owned by another agent). These are
pure service/serializer unit tests + fault-injection for except branches.
Mock OTP code is "0000" (see conftest.py).
"""

import uuid
from datetime import timedelta
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone


def _make_user(**kw):
    User = get_user_model()
    d = dict(
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        username=uuid.uuid4().hex[:12],
        password="testpass123",
    )
    d.update(kw)
    return User.objects.create_user(**d)


# ===========================================================================
# otp.services — AuthenticatorChangeService
# ===========================================================================


class RequestOldOtpTests(TestCase):
    def setUp(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        self.svc = AuthenticatorChangeService()

    def test_email_no_current_value(self):
        # change_type='email' with no email on account -> line 353-354
        user = _make_user(email="")
        result = self.svc.request_old_otp(user, "email")
        self.assertEqual(result.get("error"), "no_current_value")

    def test_phone_no_current_value(self):
        user = _make_user()  # phone is None by default
        result = self.svc.request_old_otp(user, "phone")
        self.assertEqual(result.get("error"), "no_current_value")

    def test_send_returns_error_dict_is_propagated(self):
        # result is dict with 'error' -> line 357-358
        user = _make_user()
        user.phone = "+79991234501"
        user.save()
        with patch.object(
            self.svc.phone_service,
            "send_verification_code",
            return_value={"error": "rate_limit", "retry_after": 30},
        ):
            result = self.svc.request_old_otp(user, "phone")
        self.assertEqual(result.get("error"), "rate_limit")

    def test_send_returns_none_is_send_failed(self):
        # result is None -> line 360-361
        user = _make_user()
        user.phone = "+79991234502"
        user.save()
        with patch.object(
            self.svc.phone_service, "send_verification_code", return_value=None
        ):
            result = self.svc.request_old_otp(user, "phone")
        self.assertEqual(result.get("error"), "send_failed")

    def test_success_returns_masked_target(self):
        user = _make_user()
        user.phone = "+79991234503"
        user.save()
        # mock OTP mode -> send returns a verification object (truthy, non-dict)
        result = self.svc.request_old_otp(user, "phone")
        self.assertTrue(result.get("success"))
        self.assertIn("masked_target", result)


class VerifyOldOtpTests(TestCase):
    def setUp(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        self.svc = AuthenticatorChangeService()

    def test_no_current_value(self):
        # target falsy -> line 373-374
        user = _make_user()  # no phone
        result = self.svc.verify_old_otp(user, "phone", "0000")
        self.assertEqual(result.get("error"), "no_current_value")

    def test_verification_failure_propagated(self):
        # verify_code returns error dict -> line 381-382
        user = _make_user()
        user.phone = "+79991234504"
        user.save()
        result = self.svc.verify_old_otp(user, "phone", "0000")
        # no PhoneVerification record exists -> invalid_code
        self.assertEqual(result.get("error"), "invalid_code")

    def test_success_creates_change_token(self):
        user = _make_user()
        user.phone = "+79991234505"
        user.save()
        with patch.object(
            self.svc.phone_service, "verify_code", return_value={"success": True}
        ):
            result = self.svc.verify_old_otp(user, "phone", "0000")
        self.assertTrue(result.get("success"))
        self.assertIn("change_token", result)

    def test_integrity_error_returns_duplicate_request(self):
        # create() raises IntegrityError inside the atomic block -> line 407-408
        user = _make_user()
        user.phone = "+79991234506"
        user.save()
        from stapel_auth.models import AuthenticatorChangeRequest

        with patch.object(
            self.svc.phone_service, "verify_code", return_value={"success": True}
        ):
            with patch.object(
                AuthenticatorChangeRequest.objects,
                "create",
                side_effect=IntegrityError("dup"),
            ):
                result = self.svc.verify_old_otp(user, "phone", "0000")
        self.assertEqual(result.get("error"), "duplicate_request")


class RequestNewOtpTests(TestCase):
    def setUp(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        self.svc = AuthenticatorChangeService()

    def _pending(self, user, change_type="phone", old_value="+79991234510"):
        from stapel_auth.models import (
            AuthenticatorChangeRequest,
            AuthenticatorChangeStatus,
        )

        tok = uuid.uuid4()
        AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type=change_type,
            old_value=old_value,
            new_value="",
            status=AuthenticatorChangeStatus.PENDING,
            change_token=tok,
        )
        return tok

    def test_invalid_change_token(self):
        user = _make_user()
        result = self.svc.request_new_otp(user, "phone", "+79991234511", str(uuid.uuid4()))
        self.assertEqual(result.get("error"), "invalid_change_token")

    def test_not_available(self):
        user = _make_user()
        tok = self._pending(user)
        other = _make_user()
        other.phone = "+79991234512"
        other.save()
        result = self.svc.request_new_otp(user, "phone", "+79991234512", str(tok))
        self.assertEqual(result.get("error"), "not_available")

    def test_send_error_dict_propagated(self):
        # send returns dict with error -> line 436-437
        user = _make_user()
        tok = self._pending(user)
        with patch.object(
            self.svc.phone_service,
            "send_verification_code",
            return_value={"error": "rate_limit", "retry_after": 30},
        ):
            result = self.svc.request_new_otp(user, "phone", "+79991234513", str(tok))
        self.assertEqual(result.get("error"), "rate_limit")

    def test_send_none_is_send_failed(self):
        # send returns None -> line 439-440
        user = _make_user()
        tok = self._pending(user)
        with patch.object(
            self.svc.phone_service, "send_verification_code", return_value=None
        ):
            result = self.svc.request_new_otp(user, "phone", "+79991234514", str(tok))
        self.assertEqual(result.get("error"), "send_failed")

    def test_success(self):
        user = _make_user()
        tok = self._pending(user)
        result = self.svc.request_new_otp(user, "phone", "+79991234515", str(tok))
        self.assertTrue(result.get("success"))


class VerifyNewAndApplyTests(TestCase):
    def setUp(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        self.svc = AuthenticatorChangeService()

    def _pending(self, user, new_value, change_type="phone"):
        from stapel_auth.models import (
            AuthenticatorChangeRequest,
            AuthenticatorChangeStatus,
        )

        tok = uuid.uuid4()
        AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type=change_type,
            old_value="old@example.com" if change_type == "email" else "+79991230000",
            new_value=new_value,
            status=AuthenticatorChangeStatus.PENDING,
            change_token=tok,
        )
        return tok

    def test_invalid_change_token(self):
        # request_obj None -> line 449-450
        user = _make_user()
        result = self.svc.verify_new_and_apply(
            user, "phone", "+79991234520", "0000", str(uuid.uuid4())
        )
        self.assertEqual(result.get("error"), "invalid_change_token")

    def test_value_mismatch(self):
        user = _make_user()
        tok = self._pending(user, "+79991234521")
        result = self.svc.verify_new_and_apply(
            user, "phone", "+79991234599", "0000", str(tok)
        )
        self.assertEqual(result.get("error"), "value_mismatch")

    def test_verification_failure_propagated(self):
        # verify_code returns error dict -> line 460-461
        user = _make_user()
        tok = self._pending(user, "+79991234522")
        with patch.object(
            self.svc.phone_service,
            "verify_code",
            return_value={"error": "invalid_code"},
        ):
            result = self.svc.verify_new_and_apply(
                user, "phone", "+79991234522", "0000", str(tok)
            )
        self.assertEqual(result.get("error"), "invalid_code")

    def test_success_applies_change(self):
        user = _make_user()
        tok = self._pending(user, "newapplied@example.com", change_type="email")
        with patch.object(
            self.svc.email_service, "verify_code", return_value={"success": True}
        ):
            result = self.svc.verify_new_and_apply(
                user, "email", "newapplied@example.com", "0000", str(tok)
            )
        self.assertTrue(result.get("success"))
        user.refresh_from_db()
        self.assertEqual(user.email, "newapplied@example.com")
        self.assertTrue(user.is_email_verified)


class InitiateDelayedTests(TestCase):
    def setUp(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        self.svc = AuthenticatorChangeService()

    def test_no_current_value(self):
        # no old_value -> line 481-482
        user = _make_user()  # no phone
        result = self.svc.initiate_delayed(user, "phone", "+79991234530")
        self.assertEqual(result.get("error"), "no_current_value")

    def test_not_available(self):
        user = _make_user()
        user.phone = "+79991234531"
        user.save()
        other = _make_user()
        other.phone = "+79991234532"
        other.save()
        result = self.svc.initiate_delayed(user, "phone", "+79991234532")
        self.assertEqual(result.get("error"), "not_available")

    def test_success(self):
        user = _make_user()
        user.phone = "+79991234533"
        user.save()
        result = self.svc.initiate_delayed(user, "phone", "+79991234534")
        self.assertTrue(result.get("success"))
        self.assertIn("change_request_id", result)


class GetPendingStatusTests(TestCase):
    def setUp(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        self.svc = AuthenticatorChangeService()

    def test_none_when_no_pending(self):
        user = _make_user()
        self.assertIsNone(self.svc.get_pending_status(user, "phone"))

    def test_notifications_sent_flags(self):
        # all three notification flags -> lines 533, 535, 537
        from stapel_auth.models import (
            AuthenticatorChangeRequest,
            AuthenticatorChangeStatus,
        )

        user = _make_user()
        AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type="phone",
            old_value="+79991234540",
            new_value="+79991234541",
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=10),
            notification_day_1_sent=True,
            notification_day_7_sent=True,
            notification_day_13_sent=True,
        )
        status = self.svc.get_pending_status(user, "phone")
        self.assertEqual(status["notifications_sent"], ["day_1", "day_7", "day_13"])


class CancelPendingTests(TestCase):
    def setUp(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        self.svc = AuthenticatorChangeService()

    def test_not_found(self):
        user = _make_user()
        result = self.svc.cancel_pending(user, "phone", str(uuid.uuid4()))
        self.assertEqual(result.get("error"), "not_found")

    def test_success(self):
        from stapel_auth.models import (
            AuthenticatorChangeRequest,
            AuthenticatorChangeStatus,
        )

        user = _make_user()
        req = AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type="phone",
            old_value="+79991234550",
            new_value="+79991234551",
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at=timezone.now() + timedelta(days=10),
        )
        result = self.svc.cancel_pending(user, "phone", str(req.id))
        self.assertTrue(result.get("success"))
        req.refresh_from_db()
        self.assertEqual(req.status, AuthenticatorChangeStatus.CANCELLED)


class ApplyChangePublishErrorTests(TestCase):
    def test_publish_failure_is_swallowed(self):
        # publish raises -> except branch lines 627-628 (logged, not raised)
        from stapel_auth.otp.services import AuthenticatorChangeService

        user = _make_user()
        with patch("stapel_core.bus.publish", side_effect=Exception("boom")):
            AuthenticatorChangeService._apply_change(
                user, "email", "applied2@example.com"
            )
        user.refresh_from_db()
        self.assertEqual(user.email, "applied2@example.com")
        self.assertTrue(user.is_email_verified)


class InvalidateAllTokensTests(TestCase):
    def test_loop_over_trackers_valid_and_invalid(self):
        # Real refresh token (decodes -> jti/exp -> blacklist) + garbage token
        # (decode raises -> inner except continue) -> lines 645-660
        from stapel_core.django.jwt.provider import jwt_provider

        from stapel_auth.models import RefreshTokenTracker
        from stapel_auth.otp.services import AuthenticatorChangeService

        user = _make_user()
        _access, refresh = jwt_provider.create_tokens(user)
        RefreshTokenTracker.objects.create(
            user=user,
            token=refresh,
            expires_at=timezone.now() + timedelta(days=7),
        )
        RefreshTokenTracker.objects.create(
            user=user,
            token="not-a-real-jwt-token",
            expires_at=timezone.now() + timedelta(days=7),
        )
        # Token with a jti but no exp -> `if exp:` false branch (655->650)
        import jwt as _jwt

        RefreshTokenTracker.objects.create(
            user=user,
            token=_jwt.encode({"jti": "no-exp"}, "x" * 32, algorithm="HS256"),
            expires_at=timezone.now() + timedelta(days=7),
        )
        # Token with exp already in the past -> expires_in <= 0 branch (657->650)
        past_exp = int((timezone.now() - timedelta(days=1)).timestamp())
        RefreshTokenTracker.objects.create(
            user=user,
            token=_jwt.encode(
                {"jti": "past", "exp": past_exp}, "x" * 32, algorithm="HS256"
            ),
            expires_at=timezone.now() + timedelta(days=7),
        )
        AuthenticatorChangeService._invalidate_all_tokens(user)
        # all trackers marked revoked
        self.assertFalse(
            RefreshTokenTracker.objects.filter(user=user, is_revoked=False).exists()
        )

    def test_inner_decode_exception_continues(self):
        # decode_token raising -> inner except/continue lines 659-660.
        # (Normally decode_token swallows bad tokens and returns None, so this
        # branch is only reachable via an unexpected decode failure.)
        from stapel_auth.models import RefreshTokenTracker
        from stapel_auth.otp.services import AuthenticatorChangeService

        user = _make_user()
        RefreshTokenTracker.objects.create(
            user=user,
            token="tok-inner",
            expires_at=timezone.now() + timedelta(days=7),
        )
        with patch(
            "stapel_core.core.jwt_handler.JWTHandler.decode_token",
            side_effect=Exception("decode blew up"),
        ):
            AuthenticatorChangeService._invalidate_all_tokens(user)
        self.assertFalse(
            RefreshTokenTracker.objects.filter(user=user, is_revoked=False).exists()
        )

    def test_outer_exception_is_logged(self):
        # TokenBlacklist() raising -> outer except branch lines 661-662
        from stapel_auth.models import RefreshTokenTracker
        from stapel_auth.otp.services import AuthenticatorChangeService

        user = _make_user()
        RefreshTokenTracker.objects.create(
            user=user,
            token="tok-outer",
            expires_at=timezone.now() + timedelta(days=7),
        )
        with patch(
            "stapel_core.core.token_blacklist.TokenBlacklist",
            side_effect=Exception("redis down"),
        ):
            # must not raise
            AuthenticatorChangeService._invalidate_all_tokens(user)
        self.assertTrue(RefreshTokenTracker.objects.filter(user=user).exists())


class GetValidChangeRequestTests(TestCase):
    def setUp(self):
        from stapel_auth.otp.services import AuthenticatorChangeService

        self.svc = AuthenticatorChangeService()

    def test_bad_token_returns_none(self):
        # uuid.UUID() raises ValueError -> lines 670-671
        user = _make_user()
        self.assertIsNone(
            self.svc._get_valid_change_request(user, "phone", "not-a-uuid")
        )

    def test_none_token_returns_none(self):
        # uuid.UUID(str(None)) also fails the parse -> lines 670-671
        user = _make_user()
        self.assertIsNone(self.svc._get_valid_change_request(user, "phone", None))

    def test_expired_token_returns_none(self):
        # created_at older than CHANGE_TOKEN_LIFETIME -> line 684-685
        from stapel_auth.models import (
            AuthenticatorChangeRequest,
            AuthenticatorChangeStatus,
        )

        user = _make_user()
        tok = uuid.uuid4()
        req = AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type="phone",
            old_value="+79991234560",
            new_value="",
            status=AuthenticatorChangeStatus.PENDING,
            change_token=tok,
        )
        AuthenticatorChangeRequest.objects.filter(pk=req.pk).update(
            created_at=timezone.now() - timedelta(hours=1)
        )
        self.assertIsNone(self.svc._get_valid_change_request(user, "phone", str(tok)))


# ===========================================================================
# otp.serializers
# ===========================================================================


class OtpSerializerValidationTests(TestCase):
    def test_normalize_phone_too_long(self):
        # is_valid True but formatted E.164 > 16 chars -> line 39
        from stapel_auth.otp.serializers import normalize_phone
        from stapel_core.django.api.errors import StapelValidationError

        with patch(
            "phonenumbers.format_number", return_value="+1234567890123456789"
        ):
            with self.assertRaises(StapelValidationError):
                normalize_phone("+79991234567")

    def test_normalize_phone_invalid_number(self):
        from stapel_auth.otp.serializers import normalize_phone
        from stapel_core.django.api.errors import StapelValidationError

        with self.assertRaises(StapelValidationError):
            normalize_phone("+1")

    def test_convert_anonymous_validate_phone_empty(self):
        # validate_phone falsy short-circuit -> line 113-114
        from stapel_auth.otp.serializers import ConvertAnonymousUserSerializer

        ser = ConvertAnonymousUserSerializer()
        self.assertEqual(ser.validate_phone(""), "")

    def test_convert_anonymous_requires_email_or_phone(self):
        # neither email nor phone -> line 118-119
        from stapel_auth.otp.serializers import ConvertAnonymousUserSerializer

        ser = ConvertAnonymousUserSerializer(data={"code": "0000"})
        self.assertFalse(ser.is_valid())

    def test_convert_anonymous_not_both(self):
        # both email and phone -> line 121-122
        from stapel_auth.otp.serializers import ConvertAnonymousUserSerializer

        ser = ConvertAnonymousUserSerializer(
            data={"code": "0000", "email": "x@example.com", "phone": "+79991234567"}
        )
        self.assertFalse(ser.is_valid())

    def test_instant_request_new_validate_phone_empty(self):
        # line 150-151
        from stapel_auth.otp.serializers import InstantChangeRequestNewSerializer

        ser = InstantChangeRequestNewSerializer()
        self.assertEqual(ser.validate_phone(""), "")

    def test_instant_verify_new_validate_phone_empty(self):
        # line 169-170
        from stapel_auth.otp.serializers import InstantChangeVerifyNewSerializer

        ser = InstantChangeVerifyNewSerializer()
        self.assertEqual(ser.validate_phone(""), "")

    def test_instant_verify_new_requires_email_or_phone(self):
        # validate neither -> line 174-175
        from stapel_auth.otp.serializers import InstantChangeVerifyNewSerializer

        ser = InstantChangeVerifyNewSerializer(
            data={"code": "0000", "change_token": str(uuid.uuid4())}
        )
        self.assertFalse(ser.is_valid())

    def test_delayed_initiate_validate_phone_empty(self):
        # line 187-188
        from stapel_auth.otp.serializers import DelayedChangeInitiateSerializer

        ser = DelayedChangeInitiateSerializer()
        self.assertEqual(ser.validate_phone(""), "")


# ===========================================================================
# password.services — PasswordService
# ===========================================================================


class PasswordMaskTests(TestCase):
    def test_mask_email_no_at(self):
        # line 22-23
        from stapel_auth.services import PasswordService

        self.assertEqual(PasswordService.mask_email("noatsign"), "***")
        self.assertEqual(PasswordService.mask_email(""), "***")

    def test_mask_phone_too_short(self):
        # line 30-31
        from stapel_auth.services import PasswordService

        self.assertEqual(PasswordService.mask_phone("12"), "***")
        self.assertEqual(PasswordService.mask_phone(""), "***")


class RaiseForOtpResultTests(TestCase):
    def test_falsy_non_dict_raises_500(self):
        # not a dict and falsy -> line 62-63
        from stapel_auth.services import PasswordService
        from stapel_core.django.api.errors import StapelServiceError

        with self.assertRaises(StapelServiceError) as ctx:
            PasswordService._raise_for_otp_result(None)
        self.assertEqual(ctx.exception.http_status, 500)

    def test_truthy_non_dict_is_success(self):
        # not a dict and truthy -> line 64 (return, no raise)
        from stapel_auth.services import PasswordService

        # a truthy object (e.g. a model instance stand-in) -> no exception
        self.assertIsNone(PasswordService._raise_for_otp_result(object()))


class GetAvailableMethodsTests(TestCase):
    def test_includes_totp_when_enabled(self):
        # line 112-113
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService

        user = _make_user()
        with patch(
            "stapel_auth.password.services.TOTPService.is_enabled", return_value=True
        ):
            methods = PasswordService.get_available_methods(user)
        self.assertIn(
            PasswordMethodType.TOTP, [m.method for m in methods]
        )


class SendChangeOtpTests(TestCase):
    def test_phone_no_verified_contact(self):
        # line 157-159
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService
        from stapel_core.django.api.errors import StapelServiceError

        user = _make_user()  # no phone
        with self.assertRaises(StapelServiceError) as ctx:
            PasswordService.send_change_otp(user, PasswordMethodType.PHONE)
        self.assertEqual(ctx.exception.http_status, 400)

    def test_phone_success_returns_masked(self):
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService

        user = _make_user()
        user.phone = "+79991234570"
        user.is_phone_verified = True
        user.save()
        masked = PasswordService.send_change_otp(user, PasswordMethodType.PHONE)
        self.assertIn("***", masked)

    def test_totp_not_enabled_raises(self):
        # line 163-165
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService
        from stapel_core.django.api.errors import StapelServiceError

        user = _make_user()
        with patch(
            "stapel_auth.password.services.TOTPService.is_enabled", return_value=False
        ):
            with self.assertRaises(StapelServiceError) as ctx:
                PasswordService.send_change_otp(user, PasswordMethodType.TOTP)
        self.assertEqual(ctx.exception.http_status, 400)

    def test_totp_enabled_returns_empty(self):
        # line 166
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService

        user = _make_user()
        with patch(
            "stapel_auth.password.services.TOTPService.is_enabled", return_value=True
        ):
            result = PasswordService.send_change_otp(user, PasswordMethodType.TOTP)
        self.assertEqual(result, "")

    def test_invalid_method_raises(self):
        # line 167
        from stapel_auth.services import PasswordService
        from stapel_core.django.api.errors import StapelServiceError

        user = _make_user()
        with self.assertRaises(StapelServiceError) as ctx:
            PasswordService.send_change_otp(user, "bogus_method")
        self.assertEqual(ctx.exception.http_status, 400)


class ChangeViaOtpTests(TestCase):
    def test_email_no_verified_contact(self):
        # line 181-182
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService
        from stapel_core.django.api.errors import StapelServiceError

        user = _make_user(email="")
        with self.assertRaises(StapelServiceError) as ctx:
            PasswordService.change_via_otp(
                user, PasswordMethodType.EMAIL, "0000", "NewPass123!"
            )
        self.assertEqual(ctx.exception.http_status, 400)

    def test_phone_no_verified_contact(self):
        # line 185-187
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService
        from stapel_core.django.api.errors import StapelServiceError

        user = _make_user()  # no phone
        with self.assertRaises(StapelServiceError) as ctx:
            PasswordService.change_via_otp(
                user, PasswordMethodType.PHONE, "0000", "NewPass123!"
            )
        self.assertEqual(ctx.exception.http_status, 400)

    def test_phone_success_updates_password(self):
        # line 188-189 + set_password/save/revoke
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService

        user = _make_user()
        user.phone = "+79991234571"
        user.is_phone_verified = True
        user.save()
        with patch(
            "stapel_auth.password.services.PhoneVerificationService.verify_code",
            return_value={"success": True},
        ):
            PasswordService.change_via_otp(
                user, PasswordMethodType.PHONE, "0000", "NewPass123!"
            )
        user.refresh_from_db()
        self.assertTrue(user.check_password("NewPass123!"))

    def test_totp_not_enabled_raises(self):
        # line 190-192
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService
        from stapel_core.django.api.errors import StapelServiceError

        user = _make_user()
        with patch(
            "stapel_auth.password.services.TOTPService.is_enabled", return_value=False
        ):
            with self.assertRaises(StapelServiceError) as ctx:
                PasswordService.change_via_otp(
                    user, PasswordMethodType.TOTP, "0000", "NewPass123!"
                )
        self.assertEqual(ctx.exception.http_status, 400)

    def test_totp_invalid_code_raises(self):
        # line 193-194
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService
        from stapel_core.django.api.errors import StapelServiceError

        user = _make_user()
        with patch(
            "stapel_auth.password.services.TOTPService.is_enabled", return_value=True
        ):
            with patch(
                "stapel_auth.password.services.TOTPService.verify_code",
                return_value=False,
            ):
                with self.assertRaises(StapelServiceError) as ctx:
                    PasswordService.change_via_otp(
                        user, PasswordMethodType.TOTP, "123456", "NewPass123!"
                    )
        self.assertEqual(ctx.exception.http_status, 400)

    def test_totp_success(self):
        from stapel_auth.password.dto import PasswordMethodType
        from stapel_auth.services import PasswordService

        user = _make_user()
        with patch(
            "stapel_auth.password.services.TOTPService.is_enabled", return_value=True
        ):
            with patch(
                "stapel_auth.password.services.TOTPService.verify_code",
                return_value=True,
            ):
                PasswordService.change_via_otp(
                    user, PasswordMethodType.TOTP, "123456", "NewPass123!"
                )
        user.refresh_from_db()
        self.assertTrue(user.check_password("NewPass123!"))

    def test_invalid_method_raises(self):
        # line 195-196
        from stapel_auth.services import PasswordService
        from stapel_core.django.api.errors import StapelServiceError

        user = _make_user()
        with self.assertRaises(StapelServiceError) as ctx:
            PasswordService.change_via_otp(user, "bogus", "0000", "NewPass123!")
        self.assertEqual(ctx.exception.http_status, 400)


class RevokeAllSessionsTests(TestCase):
    def test_exception_is_swallowed(self):
        # SessionService.revoke_all raises -> except lines 209-210 (logged, not raised)
        from stapel_auth.services import PasswordService

        user = _make_user()
        with patch(
            "stapel_auth.sessions.services.SessionService.revoke_all",
            side_effect=Exception("boom"),
        ):
            # must not raise
            PasswordService._revoke_all_sessions(user)


# ===========================================================================
# password.serializers
# ===========================================================================


class PasswordSerializerValidationTests(TestCase):
    def test_normalize_phone_parse_error(self):
        from stapel_auth.password.serializers import normalize_phone
        from stapel_core.django.api.errors import StapelValidationError

        with self.assertRaises(StapelValidationError):
            normalize_phone("+99999999")

    def test_normalize_phone_invalid_number(self):
        # parses successfully but is not a valid number -> line 30
        from stapel_auth.password.serializers import normalize_phone
        from stapel_core.django.api.errors import StapelValidationError

        with self.assertRaises(StapelValidationError):
            normalize_phone("+12345")

    def test_register_serializer_normalizes_phone(self):
        # PasswordRegisterSerializer.validate normalizes phone -> line 142
        from stapel_auth.password.serializers import PasswordRegisterSerializer

        ser = PasswordRegisterSerializer(
            data={"password": "NewPass123!", "phone": "+79991234567"}
        )
        self.assertTrue(ser.is_valid(), ser.errors)
        self.assertEqual(ser.validated_data["phone"], "+79991234567")

    def test_normalize_phone_too_long(self):
        # line 32-34
        from stapel_auth.password.serializers import normalize_phone
        from stapel_core.django.api.errors import StapelValidationError

        with patch(
            "phonenumbers.format_number", return_value="+1234567890123456789"
        ):
            with self.assertRaises(StapelValidationError):
                normalize_phone("+79991234567")
