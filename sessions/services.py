"""Session services: JWT tokens, session management, audit logging."""
"""
Service classes for authentication operations
"""
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import logging
import secrets
import uuid
from stapel_auth.models import PhoneVerification
from stapel_auth.password.dto import PasswordMethodType, PasswordMethod
from stapel_auth.qr.dto import QRType, QRStatus
from stapel_core.django.errors import IronServiceError, ERR_500_INTERNAL

logger = logging.getLogger(__name__)





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



def _get_client_ip(request) -> str | None:
    if not request:
        return None
    for candidate in request.META.get('HTTP_X_FORWARDED_FOR', '').split(','):
        candidate = candidate.strip()
        if candidate and not candidate.startswith(('127.', '10.', '172.', '192.168.')):
            return candidate
    return request.META.get('HTTP_X_REAL_IP') or request.META.get('REMOTE_ADDR') or None


import re as _re


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
        from stapel_auth.models import UserSession
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
        from stapel_auth.models import UserSession
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
        from stapel_auth.models import UserSession
        return UserSession.objects.filter(jti=jti).update(is_revoked=True) > 0

    @staticmethod
    def revoke_all(user, except_jti: str = None):
        from stapel_auth.models import UserSession
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
        from stapel_auth.models import UserSession
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



class AuditService:
    @staticmethod
    def log(event_type, user=None, request=None, session=None, **metadata):
        try:
            from stapel_auth.models import AuthAuditLog
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


class LoginNotificationService:
    @staticmethod
    def check_and_notify(user, session):
        """Fire async task to evaluate and optionally send notification."""
        from stapel_auth.tasks import evaluate_login_notification
        evaluate_login_notification.delay(str(user.id), str(session.id))

    @staticmethod
    def is_new_device(user, session) -> bool:
        """True if no prior session with same device_name exists (last 90 days)."""
        from stapel_auth.models import UserSession
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
        from stapel_auth.models import UserSession
        prefix = '.'.join(session.ip_address.split('.')[:3])
        return not UserSession.objects.filter(
            user=user,
            ip_address__startswith=prefix,
        ).exclude(id=session.id).exists()


# =============================================================================
# PasskeyService
# =============================================================================

