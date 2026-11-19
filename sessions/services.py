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

    One seam for the whole module: :func:`stapel_core.security.client_ip`,
    i.e. ``REMOTE_ADDR`` unless the deployment names a proxy-set header in
    ``STAPEL_SECURITY["TRUSTED_PROXY_HEADER"]``.

    This used to walk ``X-Forwarded-For`` and take the first element that
    did not look private. Any client can write that header, so a session
    row's "where you signed in from" — and the security screen built on it —
    was caller-supplied text (audit F6). Under an undeclared proxy the value
    is now the proxy's own address: wrong-but-honest beats attacker-chosen,
    and W005 tells the deployment to declare its header.
    """
    if not request:
        return None
    from stapel_core.security import client_ip

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


def _access_claims(access_token: str):
    """``(jti, expires_at)`` of an access token this process just minted.

    Read without verification on purpose: the token is our own output, handed
    over by the minting call, not something a client presented.
    """
    import datetime as _dt

    from stapel_core.django.jwt.provider import jwt_provider

    payload = jwt_provider.handler.decode_token(access_token, verify=False) or {}
    jti = str(payload.get('jti') or '')
    exp = payload.get('exp')
    if isinstance(exp, (int, float)):
        return jti, _dt.datetime.fromtimestamp(exp, tz=_dt.timezone.utc)
    return jti, None


def _access_lifetime_bound():
    """Latest moment an access token minted now can expire — the TTL used
    when only a jti was handed over."""
    from stapel_core.django.jwt.provider import jwt_provider

    return timezone.now() + jwt_provider.config.access_token_lifetime


def revoke_session_tokens(session_pk, refresh_jti: str, refresh_expires_at,
                          access_jti: str = '') -> int:
    """Blacklist every credential a revoked session can still present.

    The refresh jti, and every access token recorded for the session
    (:meth:`SessionService.record_access`) that has not expired yet — not only
    the last one. Returns how many access jtis were blacklisted. Called after
    the transaction that flipped ``is_revoked``: the blacklist is not
    transactional.
    """
    from stapel_auth.models import SessionAccessToken

    _blacklist_jti(refresh_jti, refresh_expires_at)
    now = timezone.now()
    live = list(
        SessionAccessToken.objects.filter(session_id=session_pk, expires_at__gt=now)
        .values_list('jti', 'expires_at')
    )
    for jti, expires_at in live:
        _blacklist_jti(jti, expires_at)
    if access_jti and access_jti not in {jti for jti, _ in live}:
        # Recorded before the ledger existed: bounded by the refresh expiry.
        _blacklist_jti(access_jti, refresh_expires_at)
    return len(live)


def record_minted_access(refresh_payload: dict, access_token: str) -> None:
    """stapel-core's access observer: a token minted from a refresh token is
    recorded on that refresh token's session (registered in ``apps.ready``).

    Covers the paths that mint outside this package — the JWT middleware's
    expired-token and proactive refresh, the channels re-auth, core's refresh
    view. A refresh jti that names no current session (untracked, or the
    previous jti answered inside the rotation grace window) is looked up the
    same way the refresh check honours it.
    """
    from stapel_auth.models import UserSession

    jti = (refresh_payload or {}).get('jti')
    if not jti:
        return
    session = UserSession.objects.filter(jti=jti).first()
    if session is None:
        session = SessionService.graced_session(
            jti, user_id=(refresh_payload or {}).get('user_id')
        )
    if session is not None:
        SessionService.record_access(session, access_token)


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


def _verified_jti(token: str, token_type: str) -> str:
    """The jti of *token* when it is a *token_type* token WE signed, else ``''``.

    Signature and expiry are checked: the jti selects which session is spared
    or marked current, so it must come from a credential, not from a string
    the caller assembled.
    """
    from stapel_core.django.jwt.provider import jwt_provider

    if not token:
        return ''
    try:
        payload = jwt_provider.handler.decode_token(token, verify=True) or {}
    except Exception:
        return ''  # unreadable is "vouches for nothing", never an error
    if payload.get('token_type') != token_type:
        return ''
    return str(payload.get('jti') or '')


def current_session(request):
    """The tracked ``UserSession`` *request* is authenticated with, or ``None``.

    THE one place "the caller's own session" is decided — the session list's
    ``is_current``, "revoke all except current" and the password change's
    "keep this session" all read it. Two credentials identify a session:

    - the **access token**, for every client. Access tokens carry no session
      claim; the session is found through the access-token ledger
      (``SessionAccessToken``), where every mint path records the access jti
      it handed out (:meth:`SessionService.record_access`). This is the only
      path a bearer client has — it sends no refresh token on ordinary calls.
    - the **refresh cookie**, for a browser whose access cookie expired and
      was re-minted by the middleware on this very request: its jti is the
      session row's ``jti``.

    Both tokens are signature-verified (:func:`_verified_jti`) and the row is
    looked up under ``user=request.user``, so a token can only ever select
    among the caller's own sessions. ``None`` means "this request cannot vouch
    for any session"; callers that spare a session must read that as *spare
    nothing*, never as *spare everything*.
    """
    from stapel_core.django.jwt.utils import extract_jwt_from_request

    from stapel_auth.models import SessionAccessToken, UserSession

    user = getattr(request, 'user', None)
    if user is None or not getattr(user, 'is_authenticated', False):
        return None

    access_token, refresh_token = extract_jwt_from_request(request)
    access_jti = _verified_jti(access_token, 'access')
    if access_jti:
        ledger = (
            SessionAccessToken.objects.select_related('session')
            .filter(jti=access_jti, session__user=user)
            .first()
        )
        if ledger is not None:
            return ledger.session
        # A session created before the ledger existed knows only its last one.
        session = UserSession.objects.filter(access_jti=access_jti, user=user).first()
        if session is not None:
            return session
    refresh_jti = _verified_jti(refresh_token, 'refresh')
    if refresh_jti:
        return UserSession.objects.filter(jti=refresh_jti, user=user).first()
    return None


def current_session_jti(request) -> str | None:
    """``UserSession.jti`` of :func:`current_session` — the key
    :meth:`SessionService.revoke_all` excludes on — or ``None``."""
    session = current_session(request)
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
    def create(user, jti: str, expires_at, request=None, access_jti: str = '',
               access_token: str = '') -> 'UserSession':
        """Register a session; the access token minted with it is recorded
        through :meth:`record_access` (pass ``access_token``; a bare
        ``access_jti`` is recorded with the access lifetime as its bound)."""
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
        if access_token:
            access_jti = _access_claims(access_token)[0] or access_jti
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
        if access_token or access_jti:
            SessionService.record_access(
                session, access_token, access_jti=access_jti
            )
        return session

    @staticmethod
    def create_for_pair(user, access_token: str, refresh_token: str, request=None):
        """Register the session a freshly minted pair belongs to, or ``None``
        when the refresh token carries no jti. For mint paths that sit outside
        the admission gate but still hand out a full pair."""
        import datetime as _dt

        from stapel_core.django.jwt.provider import jwt_provider

        payload = jwt_provider.handler.decode_token(refresh_token, verify=False) or {}
        jti = payload.get('jti')
        if not jti:
            return None
        exp = payload.get('exp')
        expires_at = (
            _dt.datetime.fromtimestamp(exp, tz=_dt.timezone.utc)
            if isinstance(exp, (int, float))
            else timezone.now() + timedelta(days=7)
        )
        return SessionService.create(
            user, jti, expires_at, request=request, access_token=access_token
        )

    @staticmethod
    def rotate(
        old_jti: str,
        new_jti: str,
        new_expires_at,
        user_id=None,
        new_access_jti: str = '',
        new_refresh_token: str = '',
        new_access_token: str = '',
    ):
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

        ``new_refresh_token``, when given, is cached against ``old_jti``
        (:meth:`remember_rotated_refresh`) from *inside* this same
        transaction, before it commits and releases the row lock — not
        afterward by the caller. A racing loser's own ``rotate()`` call is
        blocked on that same lock and is unblocked the instant it releases,
        so caching only after the caller regains control left a real gap in
        which the loser's CAS-lost retry (D413) could find nothing cached.
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
            update_fields = [
                'jti', 'previous_jti', 'rotated_at', 'expires_at', 'last_used_at',
            ]
            now = timezone.now()
            session.previous_jti = old_jti
            session.rotated_at = now
            session.jti = new_jti
            session.expires_at = new_expires_at
            session.last_used_at = now
            session.save(update_fields=update_fields)
            if new_access_token or new_access_jti:
                SessionService.record_access(
                    session, new_access_token, access_jti=new_access_jti
                )
            if new_refresh_token:
                SessionService.remember_rotated_refresh(old_jti, new_refresh_token)
            return True

    # -- refresh-rotation grace (D413) -------------------------------------
    #
    # Rotation is a compare-and-swap, so the loser of a race is a replay and
    # a replay revokes. A browser produces that race without any attacker:
    # a full-page reload that boots while a refresh is in flight presents
    # the jti it booted with, seconds later, and the user is logged out for
    # good. The window below answers exactly one superseded jti — the
    # session's immediately previous one — with the pair the winning
    # rotation produced, and only for `grace` seconds measured from that
    # rotation. It does not weaken reuse detection anywhere else: an older
    # jti, a revoked session, a blacklisted token and the previous jti after
    # the window all still land on `refresh_revoked`.

    _GRACE_CACHE_PREFIX = 'stapel_auth:refresh_grace:'

    @staticmethod
    def _grace_seconds() -> int:
        from stapel_auth.conf import auth_settings

        try:
            return max(0, int(auth_settings.REFRESH_ROTATION_GRACE_SECONDS or 0))
        except (TypeError, ValueError):
            return 0

    @classmethod
    def remember_rotated_refresh(cls, old_jti: str, new_refresh_token: str) -> None:
        """Keep the freshly minted refresh token reachable by the jti it replaced.

        The session row stores jtis, never tokens — that is what makes a
        database dump useless for taking a session over — so the grace answer
        needs the token itself from somewhere with a TTL. It lives in the
        cache for `grace` seconds and nowhere else; with the window off,
        nothing is written at all.

        A racing client must receive the pair the winner received: handing it
        back the superseded token instead would only move the logout to that
        token's next refresh, and (with cookie transport) would overwrite the
        winner's good cookie with a doomed one.
        """
        grace = cls._grace_seconds()
        if grace <= 0 or not old_jti or not new_refresh_token:
            return
        from django.core.cache import cache

        cache.set(f'{cls._GRACE_CACHE_PREFIX}{old_jti}', new_refresh_token, grace)

    @classmethod
    def graced_session(cls, presented_jti: str, user_id=None):
        """The session for which ``presented_jti`` is the previous jti, in window.

        Returns the ``UserSession`` when the presented jti is that session's
        immediately previous one and the rotation happened no more than
        `grace` seconds ago; ``None`` otherwise — which includes a jti two
        rotations back, a revoked session, and the window being off.
        """
        grace = cls._grace_seconds()
        if grace <= 0 or not presented_jti:
            return None

        from stapel_auth.models import UserSession

        qs = UserSession.objects.filter(
            previous_jti=presented_jti, is_revoked=False
        )
        if user_id:
            qs = qs.filter(user_id=user_id)
        session = qs.first()
        if session is None or session.rotated_at is None:
            return None
        if (timezone.now() - session.rotated_at).total_seconds() > grace:
            return None
        return session

    @classmethod
    def revoke_on_reuse(cls, presented_jti: str, user_id=None) -> bool:
        """Revoke the session whose superseded refresh jti was presented again.

        A refresh token is single-use: rotation hands out its successor. The
        same token coming back after that — outside the D413 grace window —
        means two parties hold it, and the server cannot tell which one is the
        thief, so the session both are riding ends (refresh-token reuse
        detection). The session row remembers exactly one previous jti, so
        reuse is detected for the token one rotation back; an older one is
        refused without being traceable to its session.

        Returns ``True`` when a session was revoked.
        """
        if not presented_jti:
            return False
        if cls.graced_session(presented_jti, user_id=user_id) is not None:
            return False  # a racing tab of the legitimate holder, not a replay
        from stapel_auth.models import UserSession

        qs = UserSession.objects.filter(previous_jti=presented_jti, is_revoked=False)
        if user_id:
            qs = qs.filter(user_id=user_id)
        session = qs.first()
        if session is None:
            return False
        logger.warning(
            "refresh_reuse: superseded refresh jti presented again; "
            "revoking session %s (user %s)",
            session.pk,
            session.user_id,
        )
        cls.revoke_session(session)
        return True

    @classmethod
    def current_refresh_for(cls, presented_jti: str):
        """The refresh token that superseded ``presented_jti``, while cached."""
        if cls._grace_seconds() <= 0 or not presented_jti:
            return None
        from django.core.cache import cache

        return cache.get(f'{cls._GRACE_CACHE_PREFIX}{presented_jti}')

    @staticmethod
    def record_access(session, access_token: str = '', *, access_jti: str = '') -> None:
        """THE place an access token minted for a session is recorded.

        Every mint path ends here — :meth:`create`, :meth:`rotate`, the grace
        answer, and stapel-core's mint-from-refresh through
        :func:`record_minted_access` — so revoking the session reaches every
        access token it ever handed out (:func:`revoke_session_tokens`), not
        only the last one. ``tests/test_access_token_recording.py`` holds the
        mint call sites against this.

        Pass the minted ``access_token``; a bare ``access_jti`` is recorded
        with the access lifetime as its expiry bound. A session that is
        already revoked gets the token blacklisted on the spot: the mint raced
        the revocation, and the revocation wins.
        """
        from stapel_auth.models import SessionAccessToken, UserSession

        expires_at = None
        if access_token:
            jti, expires_at = _access_claims(access_token)
            access_jti = jti or access_jti
        if not access_jti:
            return
        if expires_at is None:
            expires_at = _access_lifetime_bound()
        now = timezone.now()
        SessionAccessToken.objects.get_or_create(
            jti=access_jti,
            defaults={'session_id': session.pk, 'expires_at': expires_at},
        )
        SessionAccessToken.objects.filter(
            session_id=session.pk, expires_at__lte=now
        ).delete()
        UserSession.objects.filter(pk=session.pk).update(
            access_jti=access_jti, last_used_at=now
        )
        session.access_jti = access_jti
        session.last_used_at = now
        if UserSession.objects.filter(pk=session.pk, is_revoked=True).exists():
            _blacklist_jti(access_jti, expires_at)

    @staticmethod
    def stamp_access_jti(session, access_jti: str) -> None:
        """Record an access jti minted for a session (see :meth:`record_access`)."""
        SessionService.record_access(session, access_jti=access_jti)

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
                .values('pk', 'user_id', 'is_revoked', 'jti', 'access_jti', 'expires_at')
                .first()
            )
            if session is None:
                return False
            if not session['is_revoked']:
                UserSession.objects.filter(pk=session['pk']).update(is_revoked=True)
                _emit_session_revoked(session['user_id'], session['pk'])
        revoke_session_tokens(
            session['pk'], session['jti'], session['expires_at'], session['access_jti']
        )
        return True

    @staticmethod
    def revoke_session(session) -> None:
        """Revoke one concrete session row (the per-device "revoke this
        session" surface). Emits atomically with the flag flip (once), then
        blacklists the refresh jti and every live access token recorded for
        the session."""
        from django.db import transaction
        with transaction.atomic():
            if not session.is_revoked:
                session.is_revoked = True
                session.save(update_fields=['is_revoked'])
                _emit_session_revoked(session.user_id, session.pk)
        # Every credential the session can still present, the access tokens
        # it handed out included — idempotent, so a repeat revoke re-asserts.
        revoke_session_tokens(
            session.pk, session.jti, session.expires_at, session.access_jti
        )

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
            revoke_session_tokens(s['pk'], s['jti'], s['expires_at'], s['access_jti'])

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

    Incident 2026-08-08 (a meeting app): someone followed a meeting invite link
    into a private space and logged in for the first time in their life —
    and the first thing the product showed them was a break-in alert.

    Both checks therefore require login history to exist at all. With no
    history there is nothing to compare against, so "differs" is undefined,
    not true — silence is the only honest answer. Someone who just clicked
    "log in" doesn't need to be told they logged in.
    """

    @staticmethod
    def check_and_notify(user, session, request=None):
        """Fire async task to evaluate and optionally send notification.

        The base URL for the alert's "secure your account" link is resolved
        HERE, while the request is still in hand, and travels to the worker as
        a task argument. A worker has no ``Host`` header, so a task that read
        ``FRONTEND_URL`` itself would mail every brand's users a link to the
        primary brand's domain — the one place they are not signed in.

        A sign-in never fails because of the alert. Enqueued when celery is
        installed; when it is not, or the broker refuses the message (down,
        unreachable, an unconfigured default app on another thread), the
        alert is evaluated right here instead, and any error in that is
        logged and swallowed.
        """
        log = logger
        try:
            from stapel_auth.hosts import frontend_url_for
            from stapel_auth.tasks import evaluate_login_notification

            args = (str(user.id), str(session.id))
            kwargs = {'frontend_url': frontend_url_for(request)}
        except Exception:
            log.exception('login alert: could not prepare the evaluation; sign-in proceeds')
            return
        if hasattr(evaluate_login_notification, 'delay'):
            try:
                evaluate_login_notification.delay(*args, **kwargs)
                return
            except Exception:
                log.warning(
                    'login alert: enqueue failed, evaluating in the request',
                    exc_info=True,
                )
        try:
            evaluate_login_notification(*args, **kwargs)
        except Exception:
            log.exception('login alert: evaluation failed; sign-in proceeds')

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



def refresh_is_honoured(payload: dict) -> bool:
    """Would the refresh endpoint honour this (verified) refresh token?

    Registered with stapel-core's ``register_refresh_check`` (apps.ready), so
    every mint-from-refresh, including JWTAuthMiddleware's, gets the same
    answer the refresh view gives: the session's current jti and not
    revoked, or its previous jti inside the rotation grace window, or an
    untracked jti only when ALLOW_UNTRACKED_REFRESH is on.
    """
    from stapel_auth.conf import auth_settings
    from stapel_auth.models import UserSession

    jti = payload.get("jti")
    if not jti:
        return bool(auth_settings.ALLOW_UNTRACKED_REFRESH)
    row = UserSession.objects.filter(jti=jti).values("is_revoked").first()
    if row is not None:
        return not row["is_revoked"]
    if SessionService.graced_session(jti, user_id=payload.get("user_id")) is not None:
        return True
    tracked_elsewhere = UserSession.objects.filter(previous_jti=jti).exists()
    return bool(auth_settings.ALLOW_UNTRACKED_REFRESH) and not tracked_elsewhere
