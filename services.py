"""
Service classes for authentication operations
"""
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import logging
import secrets
import uuid
from .models import PhoneVerification
from .dto import PasswordMethodType, QRType, QRStatus, PasswordMethod
from stapel_core.django.errors import IronServiceError, ERR_500_INTERNAL

logger = logging.getLogger(__name__)


class PhoneVerificationService:
    """
    Service for phone verification using Twilio
    """

    def __init__(self):
        self.account_sid = settings.TWILIO_ACCOUNT_SID
        self.auth_token = settings.TWILIO_AUTH_TOKEN
        self.verify_service_sid = settings.TWILIO_VERIFY_SERVICE_SID
        self.use_mock_otp = getattr(settings, 'USE_MOCK_SMS_OTP', False)
        self.mock_code = getattr(settings, 'MOCK_OTP_CODE', '0000')

    def generate_code(self, force_real=False):
        """
        Generate 4-digit verification code.

        Args:
            force_real: If True, generate real OTP even in mock mode (for admin accounts)
        """
        if self.use_mock_otp and not force_real:
            return self.mock_code
        return str(secrets.randbelow(9000) + 1000)

    def send_verification_code(self, phone, device_id=None, force_real_otp=False):
        """Send verification code to phone number"""
        try:
            # Check for rate limiting - 30 seconds window
            cutoff_time = timezone.now() - timedelta(seconds=30)

            # Check recent requests by phone
            recent_by_phone = PhoneVerification.objects.filter(
                phone=phone,
                created_at__gte=cutoff_time
            ).exists()

            if recent_by_phone:
                logger.warning(f"Rate limit exceeded for phone {phone}")
                return {'error': 'rate_limit', 'retry_after': 30}

            # Check recent requests by device_id if provided
            if device_id:
                recent_by_device = PhoneVerification.objects.filter(
                    device_id=device_id,
                    created_at__gte=cutoff_time
                ).exists()

                if recent_by_device:
                    logger.warning(f"Rate limit exceeded for device {device_id}")
                    return {'error': 'rate_limit', 'retry_after': 30}

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
                expires_at=timezone.now() + timedelta(minutes=10)
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
                variables={"code": code, "expiry_minutes": 10},
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
            if verification.code == code:
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
        self.use_mock_otp = getattr(settings, 'USE_MOCK_EMAIL_OTP', False)
        self.mock_code = getattr(settings, 'MOCK_OTP_CODE', '0000')

    def generate_code(self, force_real=False):
        """
        Generate 4-digit verification code.

        Args:
            force_real: If True, generate real OTP even in mock mode (for admin accounts)
        """
        if self.use_mock_otp and not force_real:
            return self.mock_code
        return str(secrets.randbelow(9000) + 1000)

    def send_verification_code(self, email, device_id=None, force_real_otp=False):
        """Send verification code to email address"""
        try:
            from .models import EmailVerification

            # Check for rate limiting - 30 seconds window
            cutoff_time = timezone.now() - timedelta(seconds=30)

            # Check recent requests by email
            recent_by_email = EmailVerification.objects.filter(
                email=email,
                created_at__gte=cutoff_time
            ).exists()

            if recent_by_email:
                logger.warning(f"Rate limit exceeded for email {email}")
                return {'error': 'rate_limit', 'retry_after': 30}

            # Check recent requests by device_id if provided
            if device_id:
                recent_by_device = EmailVerification.objects.filter(
                    device_id=device_id,
                    created_at__gte=cutoff_time
                ).exists()

                if recent_by_device:
                    logger.warning(f"Rate limit exceeded for device {device_id}")
                    return {'error': 'rate_limit', 'retry_after': 30}

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
                expires_at=timezone.now() + timedelta(minutes=10)
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
                variables={"code": code, "expiry_minutes": 10},
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
            from .models import EmailVerification

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
            if verification.code == code:
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


class OAuthService:
    """Service for OAuth authentication — routes through provider registry."""

    def get_user_data(self, provider, access_token):
        """Fetch user data from the given OAuth provider."""
        from .oauth_providers import PROVIDER_REGISTRY
        p = PROVIDER_REGISTRY.get(provider)
        if not p:
            logger.error(f"Unsupported OAuth provider: {provider}")
            return None
        try:
            return p.get_user_data(access_token)
        except Exception as e:
            logger.error(f"Failed to get user data from {provider}: {e}")
            return None


class AuthCapabilitiesService:
    """Builds the auth capabilities response based on current settings."""

    @staticmethod
    def get_capabilities():
        from .conf import auth_settings
        from .dto import (
            AuthCapabilities,
            LoginCapabilities,
            OAuthProviderInfo,
            RegistrationCapabilities,
        )
        from .oauth_providers import get_enabled_providers

        s = auth_settings
        phone_real = not s.USE_MOCK_SMS_OTP
        email_real = not s.USE_MOCK_EMAIL_OTP
        oauth_infos = [
            OAuthProviderInfo(id=p.id, name=p.display_name)
            for p in get_enabled_providers()
        ]
        return AuthCapabilities(
            registration=RegistrationCapabilities(
                phone=s.AUTH_PHONE_REGISTRATION and phone_real,
                email=s.AUTH_EMAIL_REGISTRATION and email_real,
                password=s.AUTH_PASSWORD_REGISTRATION,
                oauth=oauth_infos if s.AUTH_OAUTH_REGISTRATION else [],
                sso=s.AUTH_SSO_REGISTRATION,
                anonymous=True,
            ),
            login=LoginCapabilities(
                phone=s.AUTH_PHONE_LOGIN and phone_real,
                email=s.AUTH_EMAIL_LOGIN and email_real,
                password=s.AUTH_PASSWORD_LOGIN,
                oauth=oauth_infos if s.AUTH_OAUTH_LOGIN else [],
                sso=s.AUTH_SSO_LOGIN,
                qr=s.AUTH_QR_LOGIN,
                passkey=s.AUTH_PASSKEY_LOGIN,
                magic_link=s.AUTH_MAGIC_LINK_LOGIN,
            ),
        )


class _TokenWrapper:
    """Simple wrapper to make string behave like SIMPLE_JWT token object"""
    def __init__(self, token: str):
        self._token = token

    def __str__(self):
        return self._token


class TokenPair:
    """
    Wrapper for access and refresh tokens with SIMPLE_JWT-compatible interface.

    Provides same interface as SIMPLE_JWT RefreshToken:
    - str(token_pair) -> refresh token string
    - str(token_pair.access_token) -> access token string
    """
    def __init__(self, access_token: str, refresh_token: str):
        self._access_token = access_token
        self._refresh_token = refresh_token
        self.access_token = _TokenWrapper(access_token)

    def __str__(self):
        return self._refresh_token


class TokenService:
    """
    Service for JWT token operations.

    Uses unified jwt_provider for all token operations to ensure
    consistent token format (RS256, kid/jku headers) across all endpoints.
    """

    @staticmethod
    def create_tokens_for_user(user):
        """Create access and refresh tokens for user with custom claims"""
        from stapel_core.django.jwt_provider import jwt_provider

        access_token, refresh_token = jwt_provider.create_tokens(user)

        return {
            'refresh': refresh_token,
            'access': access_token,
        }

    @staticmethod
    def get_refresh_token_for_user(user):
        """
        Get token pair object for user (for cookie setting).

        Returns TokenPair with SIMPLE_JWT-compatible interface:
        - str(result) -> refresh token
        - str(result.access_token) -> access token
        """
        from stapel_core.django.jwt_provider import jwt_provider

        access_token, refresh_token = jwt_provider.create_tokens(user)
        return TokenPair(access_token, refresh_token)

    @staticmethod
    def verify_token(token):
        """Verify JWT token and return payload"""
        try:
            from stapel_core.django.jwt_provider import jwt_provider
            return jwt_provider.validate_token(token)
        except Exception as e:
            logger.error(f"Failed to verify token: {e}")
            return None

    @staticmethod
    def blacklist_token(token):
        """Blacklist token (access or refresh)"""
        try:
            from stapel_core.django.jwt_provider import jwt_provider
            return jwt_provider.blacklist_token(token)
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e}")
            return False


class SecurityService:
    """
    Service for security-related operations
    """

    @staticmethod
    def check_login_attempts(identifier, time_window=timedelta(minutes=15), max_attempts=5):
        """Check if login attempts exceed threshold"""
        from .models import LoginAttempt

        cutoff_time = timezone.now() - time_window

        attempts = LoginAttempt.objects.filter(
            identifier=identifier,
            created_at__gte=cutoff_time,
            attempt_type='failed'
        ).count()

        return attempts >= max_attempts

    @staticmethod
    def cleanup_expired_anonymous_users():
        """Clean up expired anonymous users"""
        from django.contrib.auth import get_user_model

        User = get_user_model()

        expired_users = User.objects.filter(
            is_anonymous=True,
            anonymous_created_at__lt=timezone.now() - settings.ANONYMOUS_USER_LIFETIME
        )

        count = expired_users.count()
        expired_users.delete()

        logger.info(f"Cleaned up {count} expired anonymous users")
        return count

    @staticmethod
    def cleanup_expired_verifications():
        """Clean up expired phone verifications"""
        expired_verifications = PhoneVerification.objects.filter(
            expires_at__lt=timezone.now(),
            is_verified=False
        )

        count = expired_verifications.count()
        expired_verifications.delete()

        logger.info(f"Cleaned up {count} expired verifications")
        return count


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
        from .utils import mask_value

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
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

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
        from .models import AuthenticatorChangeStatus

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
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

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
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus
        from .utils import mask_value

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
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

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
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

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
                ),
                key=str(user.id),
            )
        except Exception:
            logger.exception("Failed to publish user-contact-changed event")

    @staticmethod
    def _invalidate_all_tokens(user):
        """Blacklist all refresh tokens for this user via RefreshTokenTracker + Redis."""
        from .models import RefreshTokenTracker

        # Mark all tracked refresh tokens as revoked
        RefreshTokenTracker.objects.filter(user=user, is_revoked=False).update(is_revoked=True)

        # Also blacklist via Redis if available
        try:
            from stapel_core.core.token_blacklist import TokenBlacklist
            from stapel_core.core.jwt_handler import JWTHandler
            from stapel_core.django.utils import load_jwt_config_from_settings
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
        from .models import AuthenticatorChangeRequest, AuthenticatorChangeStatus

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


# ── Password service ─────────────────────────────────────────────────────────

class PasswordService:
    """Password login, set, change, and OTP-based reset."""

    @staticmethod
    def mask_email(email: str) -> str:
        if not email or '@' not in email:
            return '***'
        local, domain = email.split('@', 1)
        masked = local[0] + '***' if len(local) > 1 else '***'
        return f"{masked}@{domain}"

    @staticmethod
    def mask_phone(phone: str) -> str:
        if not phone or len(phone) < 4:
            return '***'
        return phone[:3] + '***' + phone[-2:]

    @staticmethod
    def _check_mock_admin(user) -> None:
        """Block OTP flows for staff/superuser accounts when mock OTP is active."""
        from django.conf import settings
        from .errors import ERR_403_MOCK_OTP_ADMIN
        if (user.is_staff or user.is_superuser) and (
            getattr(settings, 'USE_MOCK_EMAIL_OTP', False) or
            getattr(settings, 'USE_MOCK_SMS_OTP', False)
        ):
            raise IronServiceError(403, ERR_403_MOCK_OTP_ADMIN)

    @staticmethod
    def _raise_for_otp_result(result) -> None:
        """Convert an OTP service result to IronServiceError. No-op on success."""
        from .errors import (
            ERR_400_CODE_EXPIRED, ERR_400_INVALID_CODE, ERR_400_INVALID_CODE_ATTEMPTS,
            ERR_400_NO_VERIFIED_CONTACT, ERR_400_INVALID_METHOD, ERR_404_USER_FOR_RESET,
            ERR_422_BLOCKED, retry_params,
        )
        from stapel_core.django.errors import ERR_429_RATE_LIMIT
        if not isinstance(result, dict):
            if not result:
                raise IronServiceError(500, ERR_500_INTERNAL)
            return  # success object
        err = result.get('error')
        if not err:
            return  # success dict
        if err == 'rate_limit':
            raise IronServiceError(429, ERR_429_RATE_LIMIT, params=retry_params(result.get('retry_after')))
        if err == 'blocked':
            raise IronServiceError(422, ERR_422_BLOCKED, params=retry_params(result.get('retry_after')))
        if err in ('expired', 'expired_retry_allowed'):
            raise IronServiceError(400, ERR_400_CODE_EXPIRED)
        if err == 'invalid_code':
            rem = result.get('attempts_remaining')
            if rem is not None:
                raise IronServiceError(400, ERR_400_INVALID_CODE_ATTEMPTS, params={'attempts_remaining': rem})
            raise IronServiceError(400, ERR_400_INVALID_CODE)
        if err == 'no_verified_contact':
            raise IronServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
        if err == 'invalid_method':
            raise IronServiceError(400, ERR_400_INVALID_METHOD)
        if err == 'user_not_found':
            raise IronServiceError(404, ERR_404_USER_FOR_RESET)
        raise IronServiceError(500, ERR_500_INTERNAL)

    @classmethod
    def get_available_methods(cls, user) -> list:
        methods = []
        if user.has_usable_password():
            methods.append(PasswordMethod(method=PasswordMethodType.PASSWORD))
        if user.email and user.is_email_verified:
            methods.append(PasswordMethod(method=PasswordMethodType.EMAIL, target=cls.mask_email(user.email)))
        if user.phone and user.is_phone_verified:
            methods.append(PasswordMethod(method=PasswordMethodType.PHONE, target=cls.mask_phone(user.phone)))
        if TOTPService.is_enabled(user):
            methods.append(PasswordMethod(method=PasswordMethodType.TOTP))
        return methods

    @staticmethod
    def login(login: str, password: str):
        """Return User or None. Checks password directly, bypassing JWT/session backends."""
        from django.contrib.auth import get_user_model
        User = get_user_model()
        user = None
        try:
            user = User.objects.get(username=login)
        except User.DoesNotExist:
            try:
                user = User.objects.get(email=login)
            except User.DoesNotExist:
                return None
        if user.check_password(password):
            return user
        return None

    @staticmethod
    def change_via_old(user, old_password: str, new_password: str) -> bool:
        if not user.check_password(old_password):
            return False
        user.set_password(new_password)
        user.save(update_fields=['password'])
        return True

    @classmethod
    def send_change_otp(cls, user, method: PasswordMethodType) -> str:
        """Send OTP for password change. Returns masked target. Raises IronServiceError."""
        from .errors import ERR_400_NO_VERIFIED_CONTACT, ERR_400_INVALID_METHOD
        cls._check_mock_admin(user)
        if method == PasswordMethodType.EMAIL:
            if not user.email or not user.is_email_verified:
                raise IronServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = EmailVerificationService().send_verification_code(user.email)
            cls._raise_for_otp_result(result)
            return cls.mask_email(user.email)
        if method == PasswordMethodType.PHONE:
            if not user.phone or not user.is_phone_verified:
                raise IronServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = PhoneVerificationService().send_verification_code(user.phone)
            cls._raise_for_otp_result(result)
            return cls.mask_phone(user.phone)
        if method == PasswordMethodType.TOTP:
            if not TOTPService.is_enabled(user):
                raise IronServiceError(400, ERR_400_INVALID_METHOD)
            return ''  # TOTP needs no "send" — code is already in the authenticator app
        raise IronServiceError(400, ERR_400_INVALID_METHOD)

    @classmethod
    def change_via_otp(cls, user, method: PasswordMethodType, code: str, new_password: str) -> None:
        """Verify OTP/TOTP and update password. Raises IronServiceError on any error."""
        from .errors import ERR_400_NO_VERIFIED_CONTACT, ERR_400_INVALID_METHOD, ERR_400_INVALID_CODE
        if method == PasswordMethodType.EMAIL:
            if not user.email or not user.is_email_verified:
                raise IronServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = EmailVerificationService().verify_code(user.email, code)
            cls._raise_for_otp_result(result)
        elif method == PasswordMethodType.PHONE:
            if not user.phone or not user.is_phone_verified:
                raise IronServiceError(400, ERR_400_NO_VERIFIED_CONTACT)
            result = PhoneVerificationService().verify_code(user.phone, code)
            cls._raise_for_otp_result(result)
        elif method == PasswordMethodType.TOTP:
            if not TOTPService.is_enabled(user):
                raise IronServiceError(400, ERR_400_INVALID_METHOD)
            if not TOTPService.verify_code(user, code):
                raise IronServiceError(400, ERR_400_INVALID_CODE)
        else:
            raise IronServiceError(400, ERR_400_INVALID_METHOD)
        user.set_password(new_password)
        user.save(update_fields=['password'])

    @classmethod
    def reset_request(cls, *, email=None, phone=None) -> str:
        """Send reset OTP. Returns masked target. Raises IronServiceError."""
        from .errors import ERR_404_USER_FOR_RESET
        from django.contrib.auth import get_user_model
        User = get_user_model()
        if email:
            try:
                user = User.objects.get(email=email, is_email_verified=True)
            except User.DoesNotExist:
                raise IronServiceError(404, ERR_404_USER_FOR_RESET)
            cls._check_mock_admin(user)
            result = EmailVerificationService().send_verification_code(email)
            cls._raise_for_otp_result(result)
            return cls.mask_email(email)
        try:
            user = User.objects.get(phone=phone, is_phone_verified=True)
        except User.DoesNotExist:
            raise IronServiceError(404, ERR_404_USER_FOR_RESET)
        cls._check_mock_admin(user)
        result = PhoneVerificationService().send_verification_code(phone)
        cls._raise_for_otp_result(result)
        return cls.mask_phone(phone)

    @classmethod
    def reset_verify(cls, *, email=None, phone=None, code: str, new_password: str):
        """Verify OTP and reset password. Returns User. Raises IronServiceError."""
        from .errors import ERR_404_USER_FOR_RESET
        from django.contrib.auth import get_user_model
        User = get_user_model()
        if email:
            result = EmailVerificationService().verify_code(email, code)
            cls._raise_for_otp_result(result)
            try:
                user = User.objects.get(email=email, is_email_verified=True)
            except User.DoesNotExist:
                raise IronServiceError(404, ERR_404_USER_FOR_RESET)
        else:
            result = PhoneVerificationService().verify_code(phone, code)
            cls._raise_for_otp_result(result)
            try:
                user = User.objects.get(phone=phone, is_phone_verified=True)
            except User.DoesNotExist:
                raise IronServiceError(404, ERR_404_USER_FOR_RESET)
        user.set_password(new_password)
        user.save(update_fields=['password'])
        return user


# ── QR auth service ──────────────────────────────────────────────────────────

import json as _json

class QRAuthService:
    """
    Short-lived QR auth keys stored in Redis.

    Types:
      session_share  – logged-in user shares session with a scanner.
      login_request  – unauth device requests login approval from a logged-in scanner.
    """
    PREFIX = "qr_auth"
    TTL = 300  # 5 minutes

    @classmethod
    def _key(cls, key: str) -> str:
        return f"{cls.PREFIX}:{key}"

    @classmethod
    def generate(cls, *, qr_type: QRType, owner_user_id=None, redirect_url: str = None) -> str:
        from django.core.cache import cache
        key = secrets.token_urlsafe(20)
        cache.set(cls._key(key), _json.dumps({
            "type": qr_type,
            "status": QRStatus.PENDING,
            "owner_user_id": str(owner_user_id) if owner_user_id else None,
            "redirect_url": redirect_url or None,
        }), cls.TTL)
        return key

    @classmethod
    def get(cls, key: str) -> dict | None:
        from django.core.cache import cache
        raw = cache.get(cls._key(key))
        return _json.loads(raw) if raw else None

    @classmethod
    def _update(cls, key: str, data: dict) -> None:
        from django.core.cache import cache
        cache.set(cls._key(key), _json.dumps(data), cls.TTL)

    @classmethod
    def fulfill_session_share(cls, key: str, *, scanner_user_id) -> bool:
        data = cls.get(key)
        if not data or data['status'] != QRStatus.PENDING:
            return False
        data['status'] = QRStatus.FULFILLED
        data['fulfilled_user_id'] = str(scanner_user_id)
        cls._update(key, data)
        return True

    @classmethod
    def fulfill_login_request(cls, key: str, *, approver_user_id, access_token: str, refresh_token: str) -> bool:
        data = cls.get(key)
        if not data or data['status'] != QRStatus.PENDING:
            return False
        data['status'] = QRStatus.FULFILLED
        data['fulfilled_user_id'] = str(approver_user_id)
        data['access_token'] = access_token
        data['refresh_token'] = refresh_token
        cls._update(key, data)
        return True

    @classmethod
    def reject(cls, key: str) -> bool:
        data = cls.get(key)
        if not data or data['status'] != QRStatus.PENDING:
            return False
        data['status'] = QRStatus.REJECTED
        cls._update(key, data)
        return True

    @classmethod
    def delete(cls, key: str) -> None:
        from django.core.cache import cache
        cache.delete(cls._key(key))

# =============================================================================
# Session Service
# =============================================================================

import re as _re


def _get_client_ip(request) -> str | None:
    if not request:
        return None
    for candidate in request.META.get('HTTP_X_FORWARDED_FOR', '').split(','):
        candidate = candidate.strip()
        if candidate and not candidate.startswith(('127.', '10.', '172.', '192.168.')):
            return candidate
    return request.META.get('HTTP_X_REAL_IP') or request.META.get('REMOTE_ADDR') or None


def _parse_ua(user_agent: str, *, ch_platform: str = '', ch_version: str = '', ch_model: str = '') -> dict:
    """Parse UA string into {type, name, details}. type matches DeviceType choices.

    ch_* are optional UA Client Hints (Sec-CH-UA-Platform, Sec-CH-UA-Platform-Version,
    Sec-CH-UA-Model) stripped of quotes — preferred over the frozen UA string on Android.
    """
    ua = (user_agent or '').strip()
    if not ua:
        return {'type': 'unknown', 'name': 'Unknown device', 'details': ''}

    ua_lower = ua.lower()

    # Non-browser / native clients
    if 'python' in ua_lower or 'urllib' in ua_lower:
        return {'type': 'api', 'name': 'API client', 'details': ''}
    if 'okhttp' in ua_lower:
        return {'type': 'phone', 'name': 'Android app', 'details': ''}
    if 'cfnetwork' in ua_lower or ('darwin' in ua_lower and 'mozilla' not in ua_lower):
        return {'type': 'phone', 'name': 'iOS app', 'details': ''}

    # Browser version extraction (Edge before Chrome to avoid false match)
    def _browser():
        for pat, name in [
            (r'Edg(?:e|A)?/(\d+)', 'Edge'),
            (r'OPR/(\d+)', 'Opera'),
            (r'Firefox/(\d+)', 'Firefox'),
            (r'Chrome/(\d+)', 'Chrome'),
            (r'Version/(\d+).*Safari', 'Safari'),
        ]:
            m = _re.search(pat, ua)
            if m:
                return f'{name} {m.group(1)}'
        return ''

    browser = _browser()

    # iPhone
    if 'iPhone' in ua:
        m = _re.search(r'iPhone OS (\d+[_\d]*)', ua)
        ver = m.group(1).replace('_', '.') if m else ''
        return {'type': 'phone', 'name': f'{browser} on iPhone' if browser else 'iPhone',
                'details': f'iOS {ver}' if ver else ''}

    # iPad
    if 'iPad' in ua:
        m = _re.search(r'CPU OS (\d+[_\d]*)', ua)
        ver = m.group(1).replace('_', '.') if m else ''
        return {'type': 'tablet', 'name': f'{browser} on iPad' if browser else 'iPad',
                'details': f'iPadOS {ver}' if ver else ''}

    # Android
    if 'Android' in ua or ch_platform.lower() == 'android':
        # Prefer Client Hints — Chrome 110+ freezes UA model/version for privacy
        if ch_version:
            major = ch_version.split('.')[0]
            os_label = f'Android {major}' if major else 'Android'
        else:
            os_label = 'Android'
        if ch_model and ch_model.lower() not in ('', 'k'):
            model = ch_model
        else:
            m_model = _re.search(r'Android [^;]+; ([^;)]+)', ua)
            model = (m_model.group(1).strip() if m_model else '').split(' Build/')[0]
            if model.lower() in ('wv', 'mobile', 'k', ''):
                model = ''
        is_tablet = 'Mobile' not in ua
        return {
            'type': 'tablet' if is_tablet else 'phone',
            'name': f'{browser} on {os_label}' if browser else os_label,
            'details': model,
        }

    # Mac
    if 'Macintosh' in ua or 'Mac OS X' in ua:
        m = _re.search(r'Mac OS X (\d+[_.]\d+)', ua)
        ver = m.group(1).replace('_', '.') if m else ''
        return {'type': 'desktop', 'name': f'{browser} on Mac' if browser else 'Mac',
                'details': f'macOS {ver}' if ver else 'macOS'}

    # Windows
    if 'Windows' in ua:
        m = _re.search(r'Windows NT (\d+\.\d+)', ua)
        nt = m.group(1) if m else ''
        win = {'10.0': '10/11', '6.3': '8.1', '6.2': '8', '6.1': '7'}.get(nt, nt)
        return {'type': 'desktop', 'name': f'{browser} on Windows' if browser else 'Windows',
                'details': f'Windows {win}' if win else 'Windows'}

    # Linux / other
    if 'Linux' in ua:
        return {'type': 'desktop', 'name': f'{browser} on Linux' if browser else 'Linux', 'details': ''}

    return {'type': 'desktop', 'name': browser or 'Desktop', 'details': ''}


def _parse_device_name(user_agent: str) -> str:
    return _parse_ua(user_agent)['name']


def _blacklist_jti(jti: str, expires_at) -> None:
    """Put a JTI into Redis blacklist. expires_at is datetime or unix timestamp."""
    if not jti:
        return
    try:
        import datetime as _dt
        from stapel_core.core.token_blacklist import TokenBlacklist
        blacklist = TokenBlacklist()
        if isinstance(expires_at, (int, float)):
            expires_at = _dt.datetime.fromtimestamp(expires_at, tz=_dt.timezone.utc)
        ttl = expires_at - _dt.datetime.now(_dt.timezone.utc)
        if ttl.total_seconds() > 0:
            blacklist.blacklist_token(jti, ttl)
    except Exception:
        logging.getLogger(__name__).exception('_blacklist_jti failed')


class SessionService:
    """Manages UserSession lifecycle: creation, rotation, revocation."""

    @staticmethod
    def create(user, jti: str, expires_at, request=None, access_jti: str = '') -> 'UserSession':
        from .models import UserSession
        ua = ''
        ip = None
        ch_platform = ch_version = ch_model = ''
        if request:
            ua = request.META.get('HTTP_USER_AGENT', '')
            ip = _get_client_ip(request)
            ch_platform = request.META.get('HTTP_SEC_CH_UA_PLATFORM', '').strip('"')
            ch_version  = request.META.get('HTTP_SEC_CH_UA_PLATFORM_VERSION', '').strip('"')
            ch_model    = request.META.get('HTTP_SEC_CH_UA_MODEL', '').strip('"')
        parsed = _parse_ua(ua, ch_platform=ch_platform, ch_version=ch_version, ch_model=ch_model)
        return UserSession.objects.create(
            user=user,
            jti=jti,
            access_jti=access_jti,
            device_name=parsed['name'],
            device_type=parsed['type'],
            device_details=parsed['details'],
            user_agent=ua[:500],
            ip_address=ip or None,
            expires_at=expires_at,
        )

    @staticmethod
    def rotate(old_jti: str, new_jti: str, new_expires_at, user_id=None, new_access_jti: str = ''):
        """
        Swap jti on a session (normal token rotation).
        Returns True on success, None if the session is revoked or a replay is detected
        (caller should deny), False if no session record exists for this user at all
        (legacy token pre-dating session tracking — caller should allow).
        """
        from .models import UserSession
        from django.utils import timezone
        try:
            session = UserSession.objects.get(jti=old_jti)
        except UserSession.DoesNotExist:
            # If the user has other active sessions, old_jti was already rotated → replay.
            # If the user has no sessions at all, this is a legacy token → allow.
            if user_id and UserSession.objects.filter(user_id=user_id, is_revoked=False).exists():
                return None
            return False
        if session.is_revoked:
            return None
        update_fields = ['jti', 'expires_at', 'last_used_at']
        session.jti = new_jti
        session.expires_at = new_expires_at
        session.last_used_at = timezone.now()
        if new_access_jti:
            session.access_jti = new_access_jti
            update_fields.append('access_jti')
        session.save(update_fields=update_fields)
        return True

    @staticmethod
    def revoke_by_jti(jti: str) -> bool:
        from .models import UserSession
        return UserSession.objects.filter(jti=jti).update(is_revoked=True) > 0

    @staticmethod
    def revoke_all(user, except_jti: str = None):
        from .models import UserSession
        qs = UserSession.objects.filter(user=user, is_revoked=False)
        if except_jti:
            qs = qs.exclude(jti=except_jti)
        sessions = list(qs.values('jti', 'access_jti', 'expires_at'))
        qs.update(is_revoked=True)
        for s in sessions:
            _blacklist_jti(s['jti'], s['expires_at'])
            _blacklist_jti(s['access_jti'], s['expires_at'])

    @staticmethod
    def get_active(user):
        from .models import UserSession
        from django.utils import timezone
        return UserSession.objects.filter(
            user=user,
            is_revoked=False,
            expires_at__gt=timezone.now(),
        )


# =============================================================================
# TOTP Service
# =============================================================================

import hashlib as _hashlib
import secrets as _secrets


class TOTPService:
    BACKUP_CODE_COUNT = 8
    STEP_UP_TTL = 900        # 15 min
    CHALLENGE_TTL = 300      # 5 min
    TOTP_WINDOW = 1          # ±1 step tolerance

    # ── setup ────────────────────────────────────────────────────────────────

    @classmethod
    def setup(cls, user) -> dict:
        """
        Start TOTP enrollment. Returns secret + otpauth URI.
        Creates/replaces a pending (is_active=False) TOTPDevice.
        """
        import pyotp
        from .models import TOTPDevice
        from django.conf import settings

        secret = pyotp.random_base32()
        issuer = getattr(settings, 'TOTP_ISSUER', 'IronMemo')
        label = user.email or user.phone or str(user.id)
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=label, issuer_name=issuer)

        TOTPDevice.objects.update_or_create(
            user=user,
            defaults={'secret': secret, 'is_active': False,
                      'backup_codes': [], 'confirmed_at': None},
        )
        return {'secret': secret, 'qr_uri': uri}

    @classmethod
    def confirm(cls, user, code: str) -> list:
        """
        Verify the first TOTP code, activate the device.
        Returns plain backup codes (shown once, then hashed-only).
        Raises ValueError on wrong code or no pending device.
        """
        import pyotp
        from .models import TOTPDevice
        from django.utils import timezone

        try:
            device = TOTPDevice.objects.get(user=user)
        except TOTPDevice.DoesNotExist:
            raise ValueError('no_pending_device')

        totp = pyotp.TOTP(device.secret)
        if not totp.verify(code, valid_window=cls.TOTP_WINDOW):
            raise ValueError('invalid_code')

        plain_codes = [_secrets.token_hex(4).upper() + '-' + _secrets.token_hex(4).upper()
                       for _ in range(cls.BACKUP_CODE_COUNT)]
        hashed_codes = [_hashlib.sha256(c.replace('-', '').encode()).hexdigest()
                        for c in plain_codes]

        device.is_active = True
        device.backup_codes = hashed_codes
        device.confirmed_at = timezone.now()
        device.save()
        return plain_codes

    @classmethod
    def disable(cls, user, code: str = None, backup_code: str = None) -> bool:
        """Disable TOTP. Requires valid code or backup code."""
        from .models import TOTPDevice
        try:
            device = TOTPDevice.objects.get(user=user, is_active=True)
        except TOTPDevice.DoesNotExist:
            return False
        if not cls._verify_any(device, code=code, backup_code=backup_code):
            return False
        device.delete()
        return True

    @classmethod
    def force_disable(cls, user) -> bool:
        """Disable TOTP without code check. Call only after external OTP verification."""
        from .models import TOTPDevice
        return TOTPDevice.objects.filter(user=user, is_active=True).delete()[0] > 0

    # ── verification helpers ─────────────────────────────────────────────────

    @classmethod
    def verify_code(cls, user, code: str) -> bool:
        import pyotp
        from .models import TOTPDevice
        try:
            device = TOTPDevice.objects.get(user=user, is_active=True)
        except TOTPDevice.DoesNotExist:
            return False
        return pyotp.TOTP(device.secret).verify(code, valid_window=cls.TOTP_WINDOW)

    @classmethod
    def verify_backup_code(cls, user, backup_code: str) -> bool:
        from .models import TOTPDevice
        try:
            device = TOTPDevice.objects.get(user=user, is_active=True)
        except TOTPDevice.DoesNotExist:
            return False
        h = _hashlib.sha256(backup_code.replace('-', '').encode()).hexdigest()
        if h not in device.backup_codes:
            return False
        device.backup_codes = [c for c in device.backup_codes if c != h]
        device.save(update_fields=['backup_codes'])
        return True

    @classmethod
    def _verify_any(cls, device, code=None, backup_code=None) -> bool:
        import pyotp
        if code:
            return pyotp.TOTP(device.secret).verify(code, valid_window=cls.TOTP_WINDOW)
        if backup_code:
            h = _hashlib.sha256(backup_code.replace('-', '').encode()).hexdigest()
            if h in device.backup_codes:
                device.backup_codes = [c for c in device.backup_codes if c != h]
                device.save(update_fields=['backup_codes'])
                return True
        return False

    @classmethod
    def is_enabled(cls, user) -> bool:
        from .models import TOTPDevice
        return TOTPDevice.objects.filter(user=user, is_active=True).exists()

    @classmethod
    def backup_codes_remaining(cls, user) -> int | None:
        from .models import TOTPDevice
        try:
            device = TOTPDevice.objects.get(user=user, is_active=True)
            return len(device.backup_codes)
        except TOTPDevice.DoesNotExist:
            return None

    # ── challenge (2FA on login) ─────────────────────────────────────────────

    @classmethod
    def create_challenge(cls, user_id: str) -> str:
        """Store a short-lived challenge in Redis; return opaque token."""
        from django.core.cache import cache
        token = _secrets.token_urlsafe(32)
        cache.set(f'totp_challenge:{token}', str(user_id), cls.CHALLENGE_TTL)
        return token

    @classmethod
    def resolve_challenge(cls, challenge_token: str, code: str = None,
                          backup_code: str = None):
        """
        Verify TOTP code against a challenge token.
        Returns user or None on failure. Clears the challenge on success.
        """
        from django.core.cache import cache
        from django.contrib.auth import get_user_model

        key = f'totp_challenge:{challenge_token}'
        user_id = cache.get(key)
        if not user_id:
            return None

        User = get_user_model()
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None

        from .models import TOTPDevice
        try:
            device = TOTPDevice.objects.get(user=user, is_active=True)
        except TOTPDevice.DoesNotExist:
            return None

        ok = cls._verify_any(device, code=code, backup_code=backup_code)
        if ok:
            cache.delete(key)
            return user
        return None

    # ── step-up ──────────────────────────────────────────────────────────────

    @classmethod
    def create_step_up(cls, user, code: str) -> str | None:
        """Verify TOTP code and issue a step-up token. Returns None on bad code."""
        if not cls.verify_code(user, code):
            return None
        from django.core.cache import cache
        token = _secrets.token_urlsafe(32)
        cache.set(f'step_up:{user.id}:{token}', '1', cls.STEP_UP_TTL)
        return token

    @classmethod
    def consume_step_up(cls, user, token: str) -> bool:
        """Check (and delete) a step-up token for the given user."""
        from django.core.cache import cache
        key = f'step_up:{user.id}:{token}'
        val = cache.get(key)
        if val:
            cache.delete(key)
            return True
        return False


# =============================================================================
# AuditService
# =============================================================================

class AuditService:
    @staticmethod
    def log(event_type, user=None, request=None, session=None, **metadata):
        try:
            from .models import AuthAuditLog
            ip = None
            ua = ''
            if request:
                ip = _get_client_ip(request)
                ua = request.META.get('HTTP_USER_AGENT', '')[:500]
            AuthAuditLog.objects.create(
                user=user,
                session=session,
                event_type=event_type,
                ip_address=ip,
                user_agent=ua,
                metadata=metadata,
            )
        except Exception:
            import logging
            logging.getLogger(__name__).exception('AuditService.log failed silently')


# =============================================================================
# LockoutService  (Redis-based, no schema changes needed)
# =============================================================================

class LockoutService:
    # (attempts_threshold, lockout_seconds)
    THRESHOLDS = [(5, 15 * 60), (10, 60 * 60), (20, 24 * 60 * 60)]
    WINDOW = 60 * 60  # rolling 1-hour window for counting attempts

    @staticmethod
    def _keys(identifier: str):
        safe = identifier.replace(':', '_')
        return f'lockout_attempts:{safe}', f'lockout_lock:{safe}'

    @classmethod
    def record_failure(cls, identifier: str) -> int:
        """Increment failure counter. Returns current count."""
        from django.core.cache import cache
        attempts_key, _ = cls._keys(identifier)
        count = (cache.get(attempts_key) or 0) + 1
        cache.set(attempts_key, count, cls.WINDOW)
        return count

    @classmethod
    def apply_lockout(cls, identifier: str, count: int, user=None, request=None):
        """Lock the identifier if count crosses a threshold. Logs audit event."""
        from django.core.cache import cache
        _, lock_key = cls._keys(identifier)
        for threshold, duration in reversed(cls.THRESHOLDS):
            if count >= threshold:
                cache.set(lock_key, {'count': count}, duration)
                AuditService.log(
                    'account_locked', user=user, request=request,
                    identifier=identifier, duration_seconds=duration, attempt_count=count,
                )
                return duration
        return None

    @classmethod
    def check(cls, identifier: str):
        """Returns (is_locked, retry_after_seconds)."""
        from django.core.cache import cache
        _, lock_key = cls._keys(identifier)
        val = cache.get(lock_key)
        if val is None:
            return False, 0
        ttl = cache.ttl(lock_key) if hasattr(cache, 'ttl') else 0
        return True, max(ttl, 1)

    @classmethod
    def clear(cls, identifier: str):
        from django.core.cache import cache
        attempts_key, lock_key = cls._keys(identifier)
        cache.delete(attempts_key)
        cache.delete(lock_key)


# =============================================================================
# MagicLinkService
# =============================================================================

class MagicLinkService:
    TTL = 15 * 60          # 15 minutes
    RATE_LIMIT = 3         # max sends per hour per email
    RATE_WINDOW = 60 * 60

    @classmethod
    def _token_key(cls, token: str) -> str:
        return f'magic_link:{token}'

    @classmethod
    def _rate_key(cls, email: str) -> str:
        return f'magic_link_rate:{email.lower()}'

    @classmethod
    def create(cls, user, redirect_url: str = '/') -> str | None:
        """Create a magic link token. Returns None if rate-limited."""
        import secrets
        from django.core.cache import cache
        rate_key = cls._rate_key(user.email)
        count = cache.get(rate_key) or 0
        if count >= cls.RATE_LIMIT:
            return None
        cache.set(rate_key, count + 1, cls.RATE_WINDOW)
        token = secrets.token_urlsafe(32)
        cache.set(cls._token_key(token), {'user_id': str(user.id), 'redirect_url': redirect_url or '/'}, cls.TTL)
        return token

    @classmethod
    def peek(cls, token: str) -> dict | None:
        """Read token without consuming it. Returns data or None."""
        from django.core.cache import cache
        return cache.get(cls._token_key(token))

    @classmethod
    def consume(cls, token: str) -> dict | None:
        """Consume token, returns {'user_id': ..., 'redirect_url': ...} or None."""
        from django.core.cache import cache
        key = cls._token_key(token)
        data = cache.get(key)
        if not data:
            return None
        cache.delete(key)
        return data

    @classmethod
    def send(cls, user, request=None, redirect_url: str = '/'):
        """Create token, enqueue email send. Returns False if rate-limited."""
        token = cls.create(user, redirect_url=redirect_url)
        if token is None:
            return False
        from django.conf import settings
        from stapel_core.notifications import request_notification
        # Link goes directly to the backend verify endpoint — sets cookies and redirects.
        # Backend URL is proxied at the same origin as the frontend under /auth/api/.
        base_url = getattr(settings, 'FRONTEND_URL', 'https://app.ironmemo.com')
        link = f'{base_url}/auth/api/magic/verify/?token={token}'
        request_notification(
            notification_type='magic_link_login',
            email=user.email,
            variables={'link': link},
            source_service='auth',
        )
        AuditService.log('magic_link_sent', user=user, request=request)
        return True


# =============================================================================
# LoginNotificationService
# =============================================================================

class LoginNotificationService:
    @staticmethod
    def check_and_notify(user, session):
        """Fire async task to evaluate and optionally send notification."""
        from stapel_auth.tasks import evaluate_login_notification
        evaluate_login_notification.delay(str(user.id), str(session.id))

    @staticmethod
    def is_new_device(user, session) -> bool:
        """True if no prior session with same device_name exists (last 90 days)."""
        from .models import UserSession
        from django.utils import timezone
        from datetime import timedelta
        cutoff = timezone.now() - timedelta(days=90)
        return not UserSession.objects.filter(
            user=user,
            device_name=session.device_name,
            created_at__gte=cutoff,
            is_revoked=False,
        ).exclude(id=session.id).exists()

    @staticmethod
    def is_suspicious_ip(user, session) -> bool:
        """True if this /24 IP prefix has never been seen for this user."""
        if not session.ip_address:
            return False
        from .models import UserSession
        prefix = '.'.join(session.ip_address.split('.')[:3])
        return not UserSession.objects.filter(
            user=user,
            ip_address__startswith=prefix,
        ).exclude(id=session.id).exists()


# =============================================================================
# PasskeyService
# =============================================================================

class PasskeyService:
    @staticmethod
    def _rp_config():
        from django.conf import settings
        return (
            getattr(settings, 'PASSKEY_RP_ID', 'app.ironmemo.com'),
            getattr(settings, 'PASSKEY_RP_NAME', 'IronMemo'),
            getattr(settings, 'PASSKEY_ORIGIN', 'https://app.ironmemo.com'),
        )

    @classmethod
    def registration_begin(cls, user) -> dict:
        import webauthn
        from webauthn.helpers.structs import (
            AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement,
        )
        from django.core.cache import cache
        rp_id, rp_name, _ = cls._rp_config()
        from .models import PasskeyCredential
        existing = [
            webauthn.helpers.structs.PublicKeyCredentialDescriptor(id=bytes(c.credential_id))
            for c in PasskeyCredential.objects.filter(user=user, is_active=True)
        ]
        options = webauthn.generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=str(user.id).encode(),
            user_name=user.email or user.username,
            user_display_name=user.get_full_name() or user.username,
            exclude_credentials=existing,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.PREFERRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
        )
        options_json = webauthn.options_to_json(options)
        cache.set(f'passkey_reg:{user.id}', options.challenge, 300)
        return options_json

    @staticmethod
    def _build_registration_credential(data: dict):
        import webauthn
        from webauthn.helpers.structs import (
            RegistrationCredential, AuthenticatorAttestationResponse,
            AuthenticatorAttachment, AuthenticatorTransport,
        )
        resp = data['response']
        transports = [AuthenticatorTransport(t) for t in resp.get('transports', [])] or None
        return RegistrationCredential(
            id=data['id'],
            raw_id=webauthn.base64url_to_bytes(data.get('rawId') or data['id']),
            response=AuthenticatorAttestationResponse(
                client_data_json=webauthn.base64url_to_bytes(resp['clientDataJSON']),
                attestation_object=webauthn.base64url_to_bytes(resp['attestationObject']),
                transports=transports,
            ),
            authenticator_attachment=AuthenticatorAttachment(data['authenticatorAttachment'])
                if data.get('authenticatorAttachment') else None,
        )

    @staticmethod
    def _build_authentication_credential(data: dict):
        import webauthn
        from webauthn.helpers.structs import (
            AuthenticationCredential, AuthenticatorAssertionResponse,
            AuthenticatorAttachment,
        )
        resp = data['response']
        return AuthenticationCredential(
            id=data['id'],
            raw_id=webauthn.base64url_to_bytes(data.get('rawId') or data['id']),
            response=AuthenticatorAssertionResponse(
                client_data_json=webauthn.base64url_to_bytes(resp['clientDataJSON']),
                authenticator_data=webauthn.base64url_to_bytes(resp['authenticatorData']),
                signature=webauthn.base64url_to_bytes(resp['signature']),
                user_handle=webauthn.base64url_to_bytes(resp['userHandle'])
                    if resp.get('userHandle') else None,
            ),
            authenticator_attachment=AuthenticatorAttachment(data['authenticatorAttachment'])
                if data.get('authenticatorAttachment') else None,
        )

    @classmethod
    def registration_complete(cls, user, credential_data: dict, device_name: str = '') -> 'PasskeyCredential':
        import webauthn
        from django.core.cache import cache
        rp_id, _, origin = cls._rp_config()
        challenge = cache.get(f'passkey_reg:{user.id}')
        if not challenge:
            raise ValueError('challenge_expired')
        cache.delete(f'passkey_reg:{user.id}')
        credential = cls._build_registration_credential(credential_data)
        verification = webauthn.verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
        from .models import PasskeyCredential
        pc = PasskeyCredential.objects.create(
            user=user,
            credential_id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            aaguid=str(verification.aaguid) if verification.aaguid else '',
            device_name=device_name or 'Passkey',
            transports=list(credential.response.transports or []),
        )
        AuditService.log('passkey_registered', user=user, device_name=pc.device_name)
        return pc

    @classmethod
    def authentication_begin(cls, user=None) -> tuple[str, dict]:
        """Returns (session_key, options_json). user=None for usernameless flow."""
        import webauthn
        import secrets
        from webauthn.helpers.structs import UserVerificationRequirement
        from django.core.cache import cache
        rp_id, _, _ = cls._rp_config()
        allow_credentials = []
        if user:
            from .models import PasskeyCredential
            allow_credentials = [
                webauthn.helpers.structs.PublicKeyCredentialDescriptor(id=bytes(c.credential_id))
                for c in PasskeyCredential.objects.filter(user=user, is_active=True)
            ]
        options = webauthn.generate_authentication_options(
            rp_id=rp_id,
            allow_credentials=allow_credentials,
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        session_key = secrets.token_urlsafe(16)
        options_json = webauthn.options_to_json(options)
        cache.set(
            f'passkey_auth:{session_key}',
            {'challenge': options.challenge, 'user_id': str(user.id) if user else None},
            300,
        )
        return session_key, options_json

    @classmethod
    def authentication_complete(cls, session_key: str, credential_data: dict):
        """Returns (user, passkey_credential) or raises ValueError."""
        import webauthn
        from django.core.cache import cache
        rp_id, _, origin = cls._rp_config()
        stored = cache.get(f'passkey_auth:{session_key}')
        if not stored:
            raise ValueError('challenge_expired')
        cache.delete(f'passkey_auth:{session_key}')
        challenge = stored['challenge']
        credential = cls._build_authentication_credential(credential_data)
        cred_id = bytes(credential.raw_id)
        from .models import PasskeyCredential
        try:
            pc = PasskeyCredential.objects.select_related('user').get(
                credential_id=cred_id, is_active=True,
            )
        except PasskeyCredential.DoesNotExist:
            raise ValueError('unknown_credential')
        verification = webauthn.verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=bytes(pc.public_key),
            credential_current_sign_count=pc.sign_count,
        )
        pc.sign_count = verification.new_sign_count
        from django.utils import timezone
        pc.last_used_at = timezone.now()
        pc.save(update_fields=['sign_count', 'last_used_at'])
        AuditService.log('passkey_login', user=pc.user, device_name=pc.device_name)
        return pc.user, pc
