"""Session services: JWT tokens, session management, audit logging."""
"""
Service classes for authentication operations
"""
from django.utils import timezone
from datetime import timedelta
import logging

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
        from stapel_auth.staff_roles import create_tokens_for_user

        access_token, refresh_token = create_tokens_for_user(user)

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
        from stapel_auth.staff_roles import create_tokens_for_user

        access_token, refresh_token = create_tokens_for_user(user)
        return TokenPair(access_token, refresh_token)

    @staticmethod
    def verify_token(token):
        """Verify JWT token and return payload"""
        try:
            from stapel_core.django.jwt.provider import jwt_provider
            return jwt_provider.validate_token(token)
        except Exception as e:
            logger.error(f"Failed to verify token: {e}")
            return None

    @staticmethod
    def blacklist_token(token):
        """Blacklist token (access or refresh)"""
        try:
            from stapel_core.django.jwt.provider import jwt_provider
            return jwt_provider.blacklist_token(token)
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e}")
            return False



def stamp_last_login(user) -> bool:
    """Stamp ``user.last_login`` for an authentication that just succeeded.

    THE one place the field is written. Django only ever stamps it from
    ``update_last_login``, a receiver of the ``user_logged_in`` signal that
    ``django.contrib.auth.login`` sends — i.e. session login. Every flow in
    this module hands out a JWT instead and sends no such signal, so the
    column stayed NULL for accounts that had logged in for months. Hosts do
    read it: an accounting page filtering ``last_login IS NOT NULL`` found
    nobody while this module's own ``auth_audit_log`` listed their logins.

    Callers are the token-issuing *authentication* sites — above all
    :func:`stapel_auth.sessions.views._issue_session_tokens`, the choke point
    every full-session path funnels through, so a new login flow inherits the
    stamp instead of having to remember it. Token **refresh** is deliberately
    not a caller: presenting a live refresh token proves the session is still
    alive, not that anyone authenticated again.

    Writes ``update_fields=["last_login"]`` — the projection observer's fast
    path (``user_projection.PROJECTED_FIELDS``) skips its pre-save SELECT for
    exactly this write. Never raises: a bookkeeping column must not be able
    to fail a login. Returns whether the stamp landed.
    """
    if user is None or getattr(user, 'pk', None) is None:
        return False
    # pk alone is not "is this row in the database": the user model's pk is a
    # UUID with a default, so an unsaved instance already carries one and an
    # update_fields save against it silently updates nothing.
    if getattr(getattr(user, '_state', None), 'adding', False):
        return False
    if not hasattr(user, 'last_login'):
        return False
    try:
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
    except Exception:
        logger.exception('failed to stamp last_login for user %s', user.pk)
        return False
    return True


def _get_client_ip(request) -> str | None:
    """The client IP for a session row / audit entry.

    One seam for the whole module: :func:`stapel_core.netintel.client_ip`,
    i.e. ``REMOTE_ADDR`` unless the deployment names a proxy-set header in
    ``STAPEL_NETINTEL["TRUSTED_PROXY_HEADER"]``.

    This used to walk ``X-Forwarded-For`` and take the first element that
    did not look private. Any client can write that header, so a session
    row's "where you signed in from" — and the security screen built on it —
    was caller-supplied text (audit F6). Under an undeclared proxy the value
    is now the proxy's own address: wrong-but-honest beats attacker-chosen,
    and W005 tells the deployment to declare its header.
    """
    if not request:
        return None
    from stapel_core.netintel import client_ip

    return client_ip(request)


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


def _emit_session_revoked(user_id, session_id) -> None:
    """Write the ``user.session_revoked`` outbox row (schemas/emits/).

    Caller MUST hold the transaction that flips ``is_revoked`` — the outbox
    guarantee is "event leaves iff the revocation commits".
    """
    from stapel_core.comm import emit

    from stapel_auth.events import EVENT_USER_SESSION_REVOKED

    emit(  # emit-check: ok — every caller wraps this in the atomic that performs the revocation write
        EVENT_USER_SESSION_REVOKED,
        {"user_id": str(user_id), "session_id": str(session_id)},
        key=str(user_id),
        service="auth",
    )


def current_session_jti(request) -> str | None:
    """The tracked session *request* is authenticated with, or ``None``.

    Returned as the ``UserSession.jti`` (the refresh jti), which is the key
    :meth:`SessionService.revoke_all` excludes on. Both token shapes are
    accepted because both identify the same row: an access token carries the
    session in its ``refresh_jti`` claim and its own jti in
    ``UserSession.access_jti``, a refresh token carries it as ``jti``.

    ``None`` means "this request cannot vouch for any session" — an unsigned
    caller, or a token whose session row is gone. Callers that spare a
    session must read that as *spare nothing*, never as *spare everything*.

    The claims are read from an unverified decode on purpose: the request is
    already authenticated by the DRF layer, and the row is looked up under
    ``user=request.user`` — so the claim only ever *selects among the
    caller's own sessions*, it never grants anything.
    """
    from django.db.models import Q
    from stapel_core.django.jwt.provider import jwt_provider
    from stapel_core.django.jwt.utils import extract_jwt_from_request

    from stapel_auth.models import UserSession

    user = getattr(request, 'user', None)
    if user is None or not getattr(user, 'is_authenticated', False):
        return None

    access_token, refresh_token = extract_jwt_from_request(request)
    candidates = []
    for token in (access_token, refresh_token):
        if not token:
            continue
        payload = jwt_provider.handler.decode_token(token, verify=False) or {}
        candidates += [payload.get('refresh_jti'), payload.get('jti')]
    candidates = [c for c in candidates if c]
    if not candidates:
        return None

    session = UserSession.objects.filter(
        Q(jti__in=candidates) | Q(access_jti__in=candidates), user=user
    ).first()
    return session.jti if session else None


class SessionService:
    """Manages UserSession lifecycle: creation, rotation, revocation.

    Lifecycle milestones go to the transactional outbox
    (``user.session_created`` / ``user.session_revoked``, schemas in
    ``schemas/emits/``) atomically with the ORM write, mirroring
    ``staff_roles`` — subscribers (audit trails, device dashboards,
    security analytics) see exactly the sessions that committed.
    """

    @staticmethod
    def create(user, jti: str, expires_at, request=None, access_jti: str = '') -> 'UserSession':
        from django.db import transaction

        from stapel_core.comm import emit

        from stapel_auth.events import EVENT_USER_SESSION_CREATED
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
        with transaction.atomic():
            session = UserSession.objects.create(
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
            payload = {
                'user_id': str(user.pk),
                'session_id': str(session.pk),
                'device_type': session.device_type,
                'created_at': session.created_at.isoformat(),
            }
            if session.ip_address:
                # Schema field is a plain (non-nullable) string — omit when unknown.
                payload['ip_address'] = str(session.ip_address)
            emit(
                EVENT_USER_SESSION_CREATED,
                payload,
                key=str(user.pk),
                service='auth',
            )
        return session

    @staticmethod
    def rotate(old_jti: str, new_jti: str, new_expires_at, user_id=None, new_access_jti: str = ''):
        """
        Swap jti on a session (normal token rotation).
        Returns True on success, None if the session is revoked or a replay is detected
        (caller should deny), False if no session record exists for this user at all
        (untracked token — the caller decides, and denies by default).

        The whole read-decide-write runs inside one transaction with the row
        locked. Without the lock two concurrent refreshes of the same token
        both read the pre-rotation row, both decide "fine", and both mint —
        so a stolen refresh token stays usable alongside the victim's
        (audit AUTH-05). With it, one caller wins and the loser sees the row
        already rotated, which is a replay.

        The session is looked up by ``(jti, user)`` rather than by ``jti``
        alone: a jti from one user's token must never be able to rotate
        another user's session row.
        """
        from django.db import transaction

        from stapel_auth.models import UserSession

        with transaction.atomic():
            qs = UserSession.objects.select_for_update().filter(jti=old_jti)
            if user_id:
                qs = qs.filter(user_id=user_id)
            session = qs.first()
            if session is None:
                # Distinguish "already rotated" (a replay of a token this
                # user really held) from "never tracked at all".
                if user_id and UserSession.objects.filter(
                    user_id=user_id, is_revoked=False
                ).exists():
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
        """Revoke the session holding ``jti``. Returns True iff a session row
        exists for the JTI (same contract as before). The outbox event is
        emitted only when the flag actually flips (idempotent re-revokes stay
        silent)."""
        from django.db import transaction

        from stapel_auth.models import UserSession
        with transaction.atomic():
            session = (
                UserSession.objects.filter(jti=jti)
                .values('pk', 'user_id', 'is_revoked')
                .first()
            )
            if session is None:
                return False
            if not session['is_revoked']:
                UserSession.objects.filter(pk=session['pk']).update(is_revoked=True)
                _emit_session_revoked(session['user_id'], session['pk'])
        return True

    @staticmethod
    def revoke_session(session) -> None:
        """Revoke one concrete session row (the per-device "revoke this
        session" surface). No-op if already revoked; emits atomically with
        the flag flip."""
        from django.db import transaction
        with transaction.atomic():
            if session.is_revoked:
                return
            session.is_revoked = True
            session.save(update_fields=['is_revoked'])
            _emit_session_revoked(session.user_id, session.pk)

    @staticmethod
    def revoke_all(user, except_jti: str = None):
        from django.db import transaction

        from stapel_auth.models import UserSession
        qs = UserSession.objects.filter(user=user, is_revoked=False)
        if except_jti:
            qs = qs.exclude(jti=except_jti)
        with transaction.atomic():
            sessions = list(qs.values('pk', 'jti', 'access_jti', 'expires_at'))
            qs.update(is_revoked=True)
            for s in sessions:
                _emit_session_revoked(user.pk, s['pk'])
        # Redis blacklisting is non-transactional — outside the atomic block.
        for s in sessions:
            _blacklist_jti(s['jti'], s['expires_at'])
            _blacklist_jti(s['access_jti'], s['expires_at'])

    @staticmethod
    def get_active(user):
        from stapel_auth.models import UserSession
        return UserSession.objects.filter(
            user=user,
            is_revoked=False,
            expires_at__gt=timezone.now(),
        )


# =============================================================================
# TOTP Service
# =============================================================================




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
    """Login watchdog: unfamiliar device / unfamiliar network -> alert email.

    COLD START. Both predicates below ask "does this login differ from
    prior ones". A brand-new user has no prior logins, and negating an
    empty set is vacuously true — so every first-ever login was guaranteed
    to read as both a new device and a suspicious network. Every new user
    got a "suspicious login detected" email a minute after signing up.

    Incident 2026-08-08 (meettoday): someone followed a meeting invite link
    into a private space and logged in for the first time in their life —
    and the first thing the product showed them was a break-in alert.

    Both checks therefore require login history to exist at all. With no
    history there is nothing to compare against, so "differs" is undefined,
    not true — silence is the only honest answer. Someone who just clicked
    "log in" doesn't need to be told they logged in.
    """

    @staticmethod
    def check_and_notify(user, session):
        """Fire async task to evaluate and optionally send notification."""
        from stapel_auth.tasks import evaluate_login_notification
        evaluate_login_notification.delay(str(user.id), str(session.id))

    @staticmethod
    def _has_login_history(user, session) -> bool:
        """True if the user has any login besides the current one.

        Deliberately broader than either predicate below: no 90-day window,
        no revoked filter, no device match. Not "does this login resemble a
        prior one" but "does a prior one exist at all" — any session, even
        revoked and a year old, answers yes.
        """
        from stapel_auth.models import UserSession
        return UserSession.objects.filter(user=user).exclude(id=session.id).exists()

    @staticmethod
    def is_new_device(user, session) -> bool:
        """True if no prior session with same device_name exists (last 90 days).

        A first-ever login isn't a "new device" — it's the only one.
        """
        if not LoginNotificationService._has_login_history(user, session):
            return False
        from stapel_auth.models import UserSession
        cutoff = timezone.now() - timedelta(days=90)
        return not UserSession.objects.filter(
            user=user,
            device_name=session.device_name,
            created_at__gte=cutoff,
            is_revoked=False,
        ).exclude(id=session.id).exists()

    @staticmethod
    def is_suspicious_ip(user, session) -> bool:
        """True if this /24 IP prefix has never been seen for this user.

        A first-ever login isn't an "unfamiliar network" — it's the first
        known one.
        """
        if not session.ip_address:
            return False
        if not LoginNotificationService._has_login_history(user, session):
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

