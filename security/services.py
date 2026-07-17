"""Service classes for security operations: SecurityService and LockoutService."""
from django.utils import timezone
from datetime import timedelta
import logging

from stapel_auth.models import PhoneVerification

logger = logging.getLogger(__name__)


class SecurityService:
    """
    Service for security-related operations
    """

    @staticmethod
    def check_login_attempts(identifier, time_window=timedelta(minutes=15), max_attempts=5):
        """Check if login attempts exceed threshold"""
        from stapel_auth.models import LoginAttempt

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
        from stapel_auth.conf import auth_settings

        User = get_user_model()

        lifetime = timedelta(days=auth_settings.ANONYMOUS_USER_LIFETIME_DAYS)
        expired_users = User.objects.filter(
            is_anonymous=True,
            anonymous_created_at__lt=timezone.now() - lifetime
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
        from stapel_auth.sessions.services import AuditService
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
