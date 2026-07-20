"""
OTP (One-Time Password) service classes for phone and email verification,
and authenticator change flows.
"""
import hmac
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import logging
import secrets
import uuid
from stapel_auth.models import PhoneVerification
from stapel_auth.otp.constants import OTP_CODE_LENGTH  # noqa: F401 — re-exported

logger = logging.getLogger(__name__)


def promote_anonymous_session(user, *, auth_type: str) -> None:
    """Flip an anonymous guest account to registered.

    THE IDENTITY MODEL: a user becomes registered exactly when a verified
    identity ANCHOR (email, phone, or a federated identity) is attached to
    their account — never for a mere credential (password/passkey/TOTP).
    Call this once the caller has ALREADY set the anchor field(s) (email/
    phone/oauth_provider+oauth_id/etc.) and the matching ``is_*_verified``
    flag on *user*; this only flips the anonymous state itself and upgrades
    the placeholder ``anon_*`` username.

    Does NOT call ``.save()`` — the caller saves once, together with the
    anchor field(s) it just set (matching the historical single-write
    behavior of the inline branches this factors out; if the caller uses
    ``update_fields``, remember to include ``is_anonymous``, ``auth_type``
    and ``username``).
    """
    user.is_anonymous = False
    user.auth_type = auth_type
    user.upgrade_username_from_anonymous()


def _generate_numeric_code(length: int) -> str:
    """A random ``length``-digit numeric string with no leading zero."""
    lo = 10 ** (length - 1)
    span = 9 * lo
    return str(secrets.randbelow(span) + lo)


class PhoneVerificationService:
    """
    Service for phone verification using Twilio
    """

    def __init__(self):
        from stapel_auth.conf import auth_settings

        self.account_sid = getattr(settings, 'TWILIO_ACCOUNT_SID', '')
        self.auth_token = getattr(settings, 'TWILIO_AUTH_TOKEN', '')
        self.verify_service_sid = getattr(settings, 'TWILIO_VERIFY_SERVICE_SID', '')
        self.use_mock_otp = auth_settings.USE_MOCK_SMS_OTP
        self.mock_code = auth_settings.MOCK_OTP_CODE
        self.otp_ttl = auth_settings.OTP_TTL
        self.resend_cooldown = auth_settings.OTP_RESEND_COOLDOWN

    def generate_code(self, force_real=False):
        """
        Generate an OTP_CODE_LENGTH-digit verification code.

        Args:
            force_real: If True, generate real OTP even in mock mode (for admin accounts)
        """
        if self.use_mock_otp and not force_real:
            return self.mock_code
        return _generate_numeric_code(OTP_CODE_LENGTH)

    def send_verification_code(self, phone, device_id=None, force_real_otp=False):
        """Send verification code to phone number"""
        try:
            # Check for rate limiting - AUTH_OTP_RESEND_COOLDOWN window
            cutoff_time = timezone.now() - timedelta(seconds=self.resend_cooldown)

            # Check recent requests by phone
            recent_by_phone = PhoneVerification.objects.filter(
                phone=phone,
                created_at__gte=cutoff_time
            ).exists()

            if recent_by_phone:
                logger.warning(f"Rate limit exceeded for phone {phone}")
                return {'error': 'rate_limit', 'retry_after': self.resend_cooldown}

            # Check recent requests by device_id if provided
            if device_id:
                recent_by_device = PhoneVerification.objects.filter(
                    device_id=device_id,
                    created_at__gte=cutoff_time
                ).exists()

                if recent_by_device:
                    logger.warning(f"Rate limit exceeded for device {device_id}")
                    return {'error': 'rate_limit', 'retry_after': self.resend_cooldown}

            # Check if there's a blocked verification for this phone/device
            latest_verification = PhoneVerification.objects.filter(
                phone=phone
            ).order_by('-created_at').first()

            if latest_verification and latest_verification.is_blocked():
                time_remaining = int((latest_verification.blocked_until - timezone.now()).total_seconds())
                logger.warning(f"Phone {phone} is blocked until {latest_verification.blocked_until}")
                return {'error': 'blocked', 'retry_after': max(time_remaining, 0)}

            # Generate code (force real OTP for admin accounts)
            code = self.generate_code(force_real=force_real_otp)

            # Create verification record
            verification = PhoneVerification.objects.create(
                phone=phone,
                code=code,
                device_id=device_id,
                expires_at=timezone.now() + timedelta(seconds=self.otp_ttl)
            )

            # Use mock OTP in development/testing (unless forced real)
            if self.use_mock_otp and not force_real_otp:
                logger.info(f"Mock OTP mode - Verification code for {phone}: {code}")
                return verification

            # Send via notification service
            from stapel_core.notifications import request_notification
            sent = request_notification(
                notification_type="otp_code",
                phone=phone,
                variables={"code": code, "expiry_minutes": self.otp_ttl // 60},
                source_service="auth",
            )
            if not sent:
                logger.error(f"Failed to queue OTP notification for phone {phone}")
                verification.delete()
                return None
            logger.info(f"Verification code sent to {phone}")

            return verification
        except Exception as e:
            logger.error(f"Failed to send verification code: {e}")
            return None

    def verify_code(self, phone, code):
        """Verify the code for phone number"""
        try:
            # Get latest unverified verification
            verification = PhoneVerification.objects.filter(
                phone=phone,
                is_verified=False
            ).order_by('-created_at').first()

            if not verification:
                logger.warning(f"No verification found for {phone}")
                return {'error': 'invalid_code'}

            # Check if blocked
            if verification.is_blocked():
                time_remaining = int((verification.blocked_until - timezone.now()).total_seconds())
                logger.warning(f"Verification blocked for {phone}")
                return {'error': 'blocked', 'retry_after': max(time_remaining, 0)}

            # Check if expired (if expired and more than 5 minutes passed, generate new code)
            if verification.is_expired():
                # If more than 5 minutes passed, allow new request
                if timezone.now() > verification.expires_at + timedelta(minutes=5):
                    logger.info(f"Expired verification cleanup for {phone}, new request allowed")
                    return {'error': 'expired_retry_allowed'}

                logger.warning(f"Verification code expired for {phone}")
                return {'error': 'expired'}

            # Increment attempts before checking
            verification.attempts += 1

            # Verify code
            if hmac.compare_digest(str(verification.code), str(code)):
                verification.is_verified = True
                verification.blocked_until = None  # Clear block on success
                verification.save()
                return {'success': True}

            # Check if max attempts reached (5 attempts max)
            if verification.attempts >= 5:
                # Block for 10 minutes
                verification.blocked_until = timezone.now() + timedelta(minutes=10)
                verification.save()
                logger.warning(f"Too many verification attempts for {phone}, blocked for 10 minutes")
                return {'error': 'blocked', 'retry_after': 600}

            # Save incremented attempts
            verification.save()

            logger.warning(f"Invalid code for {phone}, attempt {verification.attempts}/5")
            return {'error': 'invalid_code', 'attempts_remaining': 5 - verification.attempts}
        except Exception as e:
            logger.error(f"Failed to verify code: {e}")
            return {'error': 'server_error'}


class EmailVerificationService:
    """
    Service for email verification using OTP
    """

    def __init__(self):
        from stapel_auth.conf import auth_settings

        self.use_mock_otp = auth_settings.USE_MOCK_EMAIL_OTP
        self.mock_code = auth_settings.MOCK_OTP_CODE
        self.otp_ttl = auth_settings.OTP_TTL
        self.resend_cooldown = auth_settings.OTP_RESEND_COOLDOWN

    def generate_code(self, force_real=False):
        """
        Generate an OTP_CODE_LENGTH-digit verification code.

        Args:
            force_real: If True, generate real OTP even in mock mode (for admin accounts)
        """
        if self.use_mock_otp and not force_real:
            return self.mock_code
        return _generate_numeric_code(OTP_CODE_LENGTH)

    def send_verification_code(self, email, device_id=None, force_real_otp=False):
        """Send verification code to email address"""
        try:
            from stapel_auth.models import EmailVerification

            # Check for rate limiting - AUTH_OTP_RESEND_COOLDOWN window
            cutoff_time = timezone.now() - timedelta(seconds=self.resend_cooldown)

            # Check recent requests by email
            recent_by_email = EmailVerification.objects.filter(
                email=email,
                created_at__gte=cutoff_time
            ).exists()

            if recent_by_email:
                logger.warning(f"Rate limit exceeded for email {email}")
                return {'error': 'rate_limit', 'retry_after': self.resend_cooldown}

            # Check recent requests by device_id if provided
            if device_id:
                recent_by_device = EmailVerification.objects.filter(
                    device_id=device_id,
                    created_at__gte=cutoff_time
                ).exists()

                if recent_by_device:
                    logger.warning(f"Rate limit exceeded for device {device_id}")
                    return {'error': 'rate_limit', 'retry_after': self.resend_cooldown}

            # Check if there's a blocked verification for this email/device
            latest_verification = EmailVerification.objects.filter(
                email=email
            ).order_by('-created_at').first()

            if latest_verification and latest_verification.is_blocked():
                time_remaining = int((latest_verification.blocked_until - timezone.now()).total_seconds())
                logger.warning(f"Email {email} is blocked until {latest_verification.blocked_until}")
                return {'error': 'blocked', 'retry_after': max(time_remaining, 0)}

            # Generate code (force real OTP for admin accounts)
            code = self.generate_code(force_real=force_real_otp)

            # Create verification record
            verification = EmailVerification.objects.create(
                email=email,
                code=code,
                device_id=device_id,
                expires_at=timezone.now() + timedelta(seconds=self.otp_ttl)
            )

            # Use mock OTP in development/testing (unless forced real)
            if self.use_mock_otp and not force_real_otp:
                logger.info(f"Mock OTP mode - Verification code for {email}: {code}")
                return verification

            # Send via notification service
            from stapel_core.notifications import request_notification
            sent = request_notification(
                notification_type="otp_code",
                email=email,
                variables={"code": code, "expiry_minutes": self.otp_ttl // 60},
                source_service="auth",
            )
            if not sent:
                logger.error(f"Failed to queue OTP notification for email {email}")
                verification.delete()
                return None

            logger.info(f"Verification code sent to {email}")

            return verification
        except Exception as e:
            logger.error(f"Failed to send verification code: {e}")
            return None

    def verify_code(self, email, code):
        """Verify the code for email address"""
        try:
            from stapel_auth.models import EmailVerification

            # Get latest unverified verification
            verification = EmailVerification.objects.filter(
                email=email,
                is_verified=False
            ).order_by('-created_at').first()

            if not verification:
                logger.warning(f"No verification found for {email}")
                return {'error': 'invalid_code'}

            # Check if blocked
            if verification.is_blocked():
                time_remaining = int((verification.blocked_until - timezone.now()).total_seconds())
                logger.warning(f"Verification blocked for {email}")
                return {'error': 'blocked', 'retry_after': max(time_remaining, 0)}

            # Check if expired (if expired and more than 5 minutes passed, generate new code)
            if verification.is_expired():
                # If more than 5 minutes passed, allow new request
                if timezone.now() > verification.expires_at + timedelta(minutes=5):
                    logger.info(f"Expired verification cleanup for {email}, new request allowed")
                    return {'error': 'expired_retry_allowed'}

                logger.warning(f"Verification code expired for {email}")
                return {'error': 'expired'}

            # Increment attempts before checking
            verification.attempts += 1

            # Verify code
            if hmac.compare_digest(str(verification.code), str(code)):
                verification.is_verified = True
                verification.blocked_until = None  # Clear block on success
                verification.save()
                return {'success': True}

            # Check if max attempts reached (7 attempts max for email)
            if verification.attempts >= 7:
                # Block for 10 minutes
                verification.blocked_until = timezone.now() + timedelta(minutes=10)
                verification.save()
                logger.warning(f"Too many verification attempts for {email}, blocked for 10 minutes")
                return {'error': 'blocked', 'retry_after': 600}

            # Save incremented attempts
            verification.save()

            logger.warning(f"Invalid code for {email}, attempt {verification.attempts}/7")
            return {'error': 'invalid_code', 'attempts_remaining': 7 - verification.attempts}
        except Exception as e:
            logger.error(f"Failed to verify code: {e}")
            return {'error': 'server_error'}


class AuthenticatorChangeService:
    """
    Service for authenticator (phone/email) change flows.
    Supports instant (double OTP) and delayed (14-day) flows.
    """

    CHANGE_TOKEN_LIFETIME = timedelta(minutes=30)
    DELAYED_PERIOD_DAYS = 14

    def __init__(self):
        self.phone_service = PhoneVerificationService()
        self.email_service = EmailVerificationService()

    # ── Instant flow ─────────────────────────────────────────

    def request_old_otp(self, user, change_type, device_id=None):
        """Send OTP to the user's current phone/email."""
        from stapel_auth.utils import mask_value

        if change_type == 'phone':
            target = user.phone
            if not target:
                return {'error': 'no_current_value', 'message': 'No phone number on this account.'}
            result = self.phone_service.send_verification_code(target, device_id)
        else:
            target = user.email
            if not target:
                return {'error': 'no_current_value', 'message': 'No email address on this account.'}
            result = self.email_service.send_verification_code(target, device_id)

        if isinstance(result, dict) and result.get('error'):
            return result

        if result is None:
            return {'error': 'send_failed'}

        return {'success': True, 'masked_target': mask_value(target, change_type)}

    def verify_old_otp(self, user, change_type, code):
        """
        Verify OTP sent to the user's current phone/email.
        On success, creates an AuthenticatorChangeRequest with change_token.
        """
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        target = user.phone if change_type == 'phone' else user.email
        if not target:
            return {'error': 'no_current_value'}

        if change_type == 'phone':
            result = self.phone_service.verify_code(target, code)
        else:
            result = self.email_service.verify_code(target, code)

        if isinstance(result, dict) and not result.get('success'):
            return result

        # Cancel any existing pending instant request for this user+type (atomic to prevent race)
        from django.db import transaction, IntegrityError

        change_token = uuid.uuid4()
        expires_at = timezone.now() + self.CHANGE_TOKEN_LIFETIME

        try:
            with transaction.atomic():
                AuthenticatorChangeRequest.objects.filter(
                    user=user,
                    change_type=change_type,
                    status=AuthenticatorChangeStatus.PENDING,
                    scheduled_at__isnull=True,
                ).update(status=AuthenticatorChangeStatus.CANCELLED, cancelled_at=timezone.now())

                AuthenticatorChangeRequest.objects.create(
                    user=user,
                    change_type=change_type,
                    old_value=target,
                    new_value='',  # Not known yet
                    status=AuthenticatorChangeStatus.PENDING,
                    change_token=change_token,
                )
        except IntegrityError:
            return {'error': 'duplicate_request', 'message': 'A pending change request already exists.'}

        return {
            'success': True,
            'change_token': str(change_token),
            'expires_at': expires_at.isoformat(),
        }

    def request_new_otp(self, user, change_type, new_value, change_token):
        """Validate change_token, check availability, send OTP to new_value."""

        request_obj = self._get_valid_change_request(user, change_type, change_token)
        if request_obj is None:
            return {'error': 'invalid_change_token', 'message': 'Invalid or expired change token.'}

        available = self.is_value_available(new_value, change_type, exclude_user=user)
        if not available:
            return {'error': 'not_available'}

        # Store new_value on the request
        request_obj.new_value = new_value
        request_obj.save(update_fields=['new_value'])

        if change_type == 'phone':
            result = self.phone_service.send_verification_code(new_value)
        else:
            result = self.email_service.send_verification_code(new_value)

        if isinstance(result, dict) and result.get('error'):
            return result

        if result is None:
            return {'error': 'send_failed'}

        return {'success': True}

    def verify_new_and_apply(self, user, change_type, new_value, code, change_token):
        """Verify OTP for new value, apply the change, invalidate tokens."""
        from stapel_auth.models import AuthenticatorChangeStatus

        request_obj = self._get_valid_change_request(user, change_type, change_token)
        if request_obj is None:
            return {'error': 'invalid_change_token', 'message': 'Invalid or expired change token.'}

        if request_obj.new_value != new_value:
            return {'error': 'value_mismatch', 'message': 'New value does not match the change request.'}

        if change_type == 'phone':
            result = self.phone_service.verify_code(new_value, code)
        else:
            result = self.email_service.verify_code(new_value, code)

        if isinstance(result, dict) and not result.get('success'):
            return result

        # Apply
        self._apply_change(user, change_type, new_value)

        request_obj.status = AuthenticatorChangeStatus.COMPLETED
        request_obj.completed_at = timezone.now()
        request_obj.save(update_fields=['status', 'completed_at'])

        self._invalidate_all_tokens(user)

        return {'success': True}

    # ── Delayed flow ─────────────────────────────────────────

    def initiate_delayed(self, user, change_type, new_value, device_id='', ip=None, user_agent=''):
        """Create a pending delayed change request (14-day waiting period)."""
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        old_value = user.phone if change_type == 'phone' else user.email
        if not old_value:
            return {'error': 'no_current_value', 'message': f'No {change_type} on this account.'}

        available = self.is_value_available(new_value, change_type, exclude_user=user)
        if not available:
            return {'error': 'not_available'}

        # Cancel any existing pending request for this user+type
        # (covers both delayed and instant flows to avoid unique constraint violation)
        AuthenticatorChangeRequest.objects.filter(
            user=user,
            change_type=change_type,
            status=AuthenticatorChangeStatus.PENDING,
        ).update(status=AuthenticatorChangeStatus.CANCELLED, cancelled_at=timezone.now())

        scheduled_at = timezone.now() + timedelta(days=self.DELAYED_PERIOD_DAYS)

        request_obj = AuthenticatorChangeRequest.objects.create(
            user=user,
            change_type=change_type,
            old_value=old_value,
            new_value=new_value,
            scheduled_at=scheduled_at,
            device_id=device_id,
            ip_address=ip,
            user_agent=user_agent,
        )

        return {
            'success': True,
            'change_request_id': str(request_obj.id),
            'scheduled_at': scheduled_at.isoformat(),
        }

    def get_pending_status(self, user, change_type):
        """Return pending delayed change info or None."""
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        from stapel_auth.utils import mask_value

        request_obj = AuthenticatorChangeRequest.objects.filter(
            user=user,
            change_type=change_type,
            status=AuthenticatorChangeStatus.PENDING,
            scheduled_at__isnull=False,
        ).first()

        if not request_obj:
            return None

        days_remaining = max(0, (request_obj.scheduled_at - timezone.now()).days)
        notifications_sent = []
        if request_obj.notification_day_1_sent:
            notifications_sent.append('day_1')
        if request_obj.notification_day_7_sent:
            notifications_sent.append('day_7')
        if request_obj.notification_day_13_sent:
            notifications_sent.append('day_13')

        return {
            'change_request_id': str(request_obj.id),
            'type': request_obj.change_type,
            'new_value_masked': mask_value(request_obj.new_value, request_obj.change_type),
            'created_at': request_obj.created_at.isoformat(),
            'scheduled_at': request_obj.scheduled_at.isoformat(),
            'days_remaining': days_remaining,
            'notifications_sent': notifications_sent,
        }

    def cancel_pending(self, user, change_type, change_request_id):
        """Cancel a pending delayed change request."""
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        try:
            request_obj = AuthenticatorChangeRequest.objects.get(
                id=change_request_id,
                user=user,
                change_type=change_type,
                status=AuthenticatorChangeStatus.PENDING,
            )
        except AuthenticatorChangeRequest.DoesNotExist:
            return {'error': 'not_found', 'message': 'Change request not found.'}

        request_obj.status = AuthenticatorChangeStatus.CANCELLED
        request_obj.cancelled_at = timezone.now()
        request_obj.save(update_fields=['status', 'cancelled_at'])

        return {'success': True}

    # ── Shared helpers ───────────────────────────────────────

    @staticmethod
    def is_value_available(value, change_type, exclude_user=None):
        """Check if a phone/email is available (not registered AND not reserved)."""
        from django.contrib.auth import get_user_model
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        User = get_user_model()

        if change_type == 'phone':
            qs = User.objects.filter(phone=value)
        else:
            qs = User.objects.filter(email=value)
        if exclude_user:
            qs = qs.exclude(id=exclude_user.id)
        if qs.exists():
            return False

        # Check reservation by pending change
        if AuthenticatorChangeRequest.objects.filter(
            new_value=value,
            change_type=change_type,
            status=AuthenticatorChangeStatus.PENDING,
        ).exists():
            return False

        return True

    @staticmethod
    def _apply_change(user, change_type, new_value):
        """Update the user's phone/email field and publish contact-changed event."""
        if change_type == 'phone':
            user.phone = new_value
            user.is_phone_verified = True
        else:
            user.email = new_value
            user.is_email_verified = True
        user.save()

        # Publish user-contact-changed event for notifications service
        try:
            from stapel_core.bus import publish, Event
            from stapel_core.kafka.topics import TOPIC_USER_CONTACT_CHANGED
            from stapel_core.kafka.events import EventType
            publish(
                TOPIC_USER_CONTACT_CHANGED,
                Event(
                    event_type=EventType.USER_CONTACT_CHANGED,
                    service="auth",
                    payload={
                        "user_id": str(user.id),
                        "email": user.email or "",
                        "phone": user.phone or "",
                    },
                    key=str(user.id),
                ),
            )
        except Exception:
            logger.exception("Failed to publish user-contact-changed event")

    @staticmethod
    def _invalidate_all_tokens(user):
        """Blacklist all refresh tokens for this user via RefreshTokenTracker + Redis."""
        from stapel_auth.models import RefreshTokenTracker

        # Mark all tracked refresh tokens as revoked
        RefreshTokenTracker.objects.filter(user=user, is_revoked=False).update(is_revoked=True)

        # Also blacklist via Redis if available
        try:
            from stapel_core.core.token_blacklist import TokenBlacklist
            from stapel_core.core.jwt_handler import JWTHandler
            from stapel_core.django.jwt.utils import load_jwt_config_from_settings
            from datetime import datetime, timezone as dt_timezone

            blacklist = TokenBlacklist()
            config = load_jwt_config_from_settings()
            jwt_handler = JWTHandler(config)

            tokens = RefreshTokenTracker.objects.filter(user=user)
            for tracker in tokens:
                try:
                    payload = jwt_handler.decode_token(tracker.token, verify=False)
                    if payload and 'jti' in payload:
                        exp = payload.get('exp')
                        if exp:
                            expires_in = datetime.fromtimestamp(exp, tz=dt_timezone.utc) - datetime.now(dt_timezone.utc)
                            if expires_in.total_seconds() > 0:
                                blacklist.blacklist_token(payload['jti'], expires_in)
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f"Failed to blacklist tokens via Redis for user {user.id}: {e}")

    def _get_valid_change_request(self, user, change_type, change_token):
        """Get a pending instant-flow change request by change_token."""
        from stapel_auth.models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

        try:
            token_uuid = uuid.UUID(str(change_token))
        except (ValueError, AttributeError):
            return None

        try:
            request_obj = AuthenticatorChangeRequest.objects.get(
                user=user,
                change_type=change_type,
                change_token=token_uuid,
                status=AuthenticatorChangeStatus.PENDING,
            )
        except AuthenticatorChangeRequest.DoesNotExist:
            return None

        # Check if token has expired
        if request_obj.created_at + self.CHANGE_TOKEN_LIFETIME < timezone.now():
            return None

        return request_obj
