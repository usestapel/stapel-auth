"""Magic link services."""
"""
Service classes for authentication operations
"""
import logging
import secrets

from stapel_auth.sessions.services import AuditService

logger = logging.getLogger(__name__)




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
        from stapel_core.notifications import request_notification
        # Link goes directly to the backend verify endpoint — sets cookies and redirects.
        # Backend URL is proxied at the same origin as the frontend under /auth/api/v1/.
        from stapel_auth.conf import auth_settings
        base_url = auth_settings.FRONTEND_URL or ''
        link = f'{base_url}/auth/api/v1/magic/verify/?token={token}'
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

