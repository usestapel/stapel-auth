"""System check for mock OTP providers left on in production (tag ``stapel_auth``).

E-level by design: ``USE_MOCK_SMS_OTP``/``USE_MOCK_EMAIL_OTP`` are meant for
local dev only (the shipped ``.env.local`` preset turns them on so a login
tab works without real SMS/email providers wired up — the code is written to
logs instead of actually sent). If either mock flag survives into a
``DEBUG=False`` boot, real users get a channel that looks enabled
(oauth/services.py.AuthCapabilities no longer gates ``enabled`` on the mock
flag — see the email_mock/phone_mock/methods[].mock transparency fields
instead) but whose OTP code never leaves the process: users can't complete
login/registration over that channel, and anyone with log access can
authenticate as anyone. This is exactly the "deployed as downloaded" class of
mistake ``stapel_core.django.prodguard`` exists to catch for secrets/DB
passwords — same failure shape, so it gets the same treatment here rather
than only being caught by the standalone ``deploy/check-env.sh`` text-file
gate (which does not run inside the app process/CI's ``manage.py check``).
"""
from __future__ import annotations

from django.core import checks

E001_MOCK_OTP_IN_PRODUCTION = "stapel_auth.E001"


@checks.register("stapel_auth")
def check_mock_otp_disabled_in_production(app_configs=None, **kwargs):
    """E001 — USE_MOCK_SMS_OTP/USE_MOCK_EMAIL_OTP must be off when DEBUG=False."""
    from django.conf import settings

    if getattr(settings, "DEBUG", False):
        return []

    from .conf import auth_settings

    errors = []
    if auth_settings.USE_MOCK_SMS_OTP:
        errors.append(checks.Error(
            "USE_MOCK_SMS_OTP is enabled with DEBUG=False. Phone OTP codes "
            "are being written to logs instead of sent via SMS — real users "
            "cannot complete phone login/registration, and anyone with log "
            "access can authenticate as anyone.",
            hint="Set STAPEL_AUTH['USE_MOCK_SMS_OTP'] = False (or unset the "
                 "USE_MOCK_SMS_OTP env var) and configure a real SMS "
                 "provider before deploying with DEBUG=False.",
            id=E001_MOCK_OTP_IN_PRODUCTION,
        ))
    if auth_settings.USE_MOCK_EMAIL_OTP:
        errors.append(checks.Error(
            "USE_MOCK_EMAIL_OTP is enabled with DEBUG=False. Email OTP "
            "codes are being written to logs instead of sent via email — "
            "real users cannot complete email login/registration, and "
            "anyone with log access can authenticate as anyone.",
            hint="Set STAPEL_AUTH['USE_MOCK_EMAIL_OTP'] = False (or unset "
                 "the USE_MOCK_EMAIL_OTP env var) and configure a real email "
                 "provider before deploying with DEBUG=False.",
            id=E001_MOCK_OTP_IN_PRODUCTION,
        ))
    return errors


__all__ = ["E001_MOCK_OTP_IN_PRODUCTION", "check_mock_otp_disabled_in_production"]


E002_OTP_LENGTH_OVER_CAP = "stapel_auth.E002"


@checks.register("stapel_auth")
def check_otp_length_within_cap(app_configs=None, **kwargs):
    """E002 — STAPEL_AUTH["OTP_LENGTH"] must fit the storage/wire cap.

    The generated code length is a runtime setting, but the DB columns and
    serializer max_length are pinned to ``otp.constants.OTP_CODE_LENGTH``
    (8) — a longer setting would mint codes the wire silently truncates.
    MOCK_OTP_CODE is validated against the same cap.
    """
    from .conf import auth_settings
    from .otp.constants import OTP_CODE_LENGTH

    errors = []
    length = int(auth_settings.OTP_LENGTH)
    if not (1 <= length <= OTP_CODE_LENGTH):
        errors.append(checks.Error(
            f"STAPEL_AUTH['OTP_LENGTH'] = {length} is outside 1..{OTP_CODE_LENGTH} "
            f"(the storage/wire cap OTP_CODE_LENGTH).",
            hint="Pick a length within the cap; widening the cap is a "
                 "coordinated migration-carrying change in stapel-auth.",
            id=E002_OTP_LENGTH_OVER_CAP,
        ))
    mock = str(auth_settings.MOCK_OTP_CODE or "")
    if mock and len(mock) > OTP_CODE_LENGTH:
        errors.append(checks.Error(
            f"STAPEL_AUTH['MOCK_OTP_CODE'] is {len(mock)} chars — over the "
            f"{OTP_CODE_LENGTH}-char storage/wire cap; verification would "
            "always fail.",
            hint="Use a mock code within the cap (e.g. 4-8 digits).",
            id=E002_OTP_LENGTH_OVER_CAP,
        ))
    return errors


E003_FRONTEND_URL_NOT_SET = "stapel_auth.E003"


@checks.register("stapel_auth")
def check_frontend_url_set_in_production(app_configs=None, **kwargs):
    """E003 — FRONTEND_URL must be set when DEBUG=False.

    Same failure shape as E001, one layer up the stack: this used to be a
    plain ``warnings.warn`` in ``apps.py`` (easy to miss — Python warnings
    routinely never reach a container's visible log stream). Every redirect
    this pair issues off session (SSO callback, magic link, QR
    account-conflict, OTP-challenge continuation, security email/phone
    verification links) falls back to ``auth_settings.FRONTEND_URL or ""``
    with no further validation, so an unset value most often does NOT show
    up as an empty/broken link — a host settings module with its own
    legacy flat ``FRONTEND_URL`` Django setting (the resolution order this
    pair's ``AppSettings`` documents) commonly carries a dev-friendly
    default of its own (e.g. ``http://localhost:3000``) that then leaks
    into every environment sharing that base module, silently sending real
    users' auth redirects to a developer's laptop. A host is expected to
    keep any such default confined to its OWN dev-only settings layer (see
    ``stapel_auth``'s own ``USE_MOCK_*_OTP`` split between prod-safe
    ``base``/dev-friendly ``local`` for the established pattern) so this
    check can actually catch the unset case in prod/staging.
    """
    from django.conf import settings

    if getattr(settings, "DEBUG", False):
        return []

    from .conf import auth_settings

    if auth_settings.FRONTEND_URL:
        return []
    return [checks.Error(
        "FRONTEND_URL is not set with DEBUG=False. Every redirect this pair "
        "issues off session (SSO/magic-link/QR/OTP-challenge/security "
        "verification links) falls back to an empty base and silently "
        "breaks — or, worse, resolves to a host settings module's own "
        "leftover dev default (e.g. http://localhost:3000).",
        hint="Set STAPEL_AUTH['FRONTEND_URL'] (or the FRONTEND_URL env "
             "var) to the real public origin before deploying with "
             "DEBUG=False. Keep any dev-only fallback confined to your "
             "project's own dev settings layer, never the shared base "
             "module prod/staging inherit from.",
        id=E003_FRONTEND_URL_NOT_SET,
    )]


__all__ += [
    "E003_FRONTEND_URL_NOT_SET",
    "check_frontend_url_set_in_production",
]


E004_MOCK_OTP_ON_A_PUBLIC_HOST = "stapel_auth.E004"

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0", "testserver", ""}


def _looks_public(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if host in LOCAL_HOSTS:
        return False
    if host.endswith(".local") or host.endswith(".localhost"):
        return False
    if host.startswith("192.168.") or host.startswith("10.") or host.startswith("172."):
        return False
    return True


@checks.register("stapel_auth")
def check_mock_otp_not_on_a_public_host(app_configs=None, **kwargs):
    """E004 — mock OTP on a host that is not obviously local.

    E001 ties the same hazard to ``DEBUG=False``, which is exactly the case
    a real stand escapes: dev settings keep DEBUG on, so a publicly
    reachable deployment kept accepting a fixed code for ANY address —
    "sign in as anyone" — for as long as the value stayed in its env
    template (ironmemo stand, found 2026-07-26, months after real email and
    SMS providers were wired).

    ``ALLOWED_HOSTS=['*']`` counts as public: a deployment that answers on
    any Host header is not somebody's laptop.

    A stand that deliberately runs on a pin code (a demo sandbox, say)
    silences this the standard way — ``SILENCED_SYSTEM_CHECKS =
    ["stapel_auth.E004"]`` in that settings layer. The point is that the
    intent has to be written down somewhere, instead of being inherited
    from whatever DEBUG happens to be.
    """
    from django.conf import settings

    from .conf import auth_settings

    if not (auth_settings.USE_MOCK_SMS_OTP or auth_settings.USE_MOCK_EMAIL_OTP):
        return []

    hosts = list(getattr(settings, "ALLOWED_HOSTS", []) or [])
    public = [h for h in hosts if h == "*" or _looks_public(h)]
    if not public:
        return []

    enabled = [
        name for name, on in (
            ("USE_MOCK_SMS_OTP", auth_settings.USE_MOCK_SMS_OTP),
            ("USE_MOCK_EMAIL_OTP", auth_settings.USE_MOCK_EMAIL_OTP),
        ) if on
    ]
    return [checks.Error(
        f"{' and '.join(enabled)} enabled while ALLOWED_HOSTS reaches a "
        f"non-local host ({', '.join(public[:3])}). A fixed OTP code is "
        "accepted for ANY address, so anyone who can reach this deployment "
        "can sign in as anyone.",
        hint="Turn mock OTP off for anything reachable beyond a developer "
             "machine (unset USE_MOCK_*_OTP / MOCK_OTP_CODE) and use the "
             "real email/SMS providers. Keep it to settings layers whose "
             "ALLOWED_HOSTS is local — DEBUG alone does not decide this.",
        id=E004_MOCK_OTP_ON_A_PUBLIC_HOST,
    )]


__all__ += [
    "E004_MOCK_OTP_ON_A_PUBLIC_HOST",
    "check_mock_otp_not_on_a_public_host",
]


W005_PROXY_TRUST_UNDECLARED = "stapel_auth.W005"
W006_APPENDING_PROXY_HEADER_TRUSTED = "stapel_auth.W006"

#: Settings whose presence means "this process is served through a proxy".
#: A deployment that already tells Django to believe the edge about the
#: scheme/host/port is, by its own statement, behind one.
_BEHIND_A_PROXY_SETTINGS = (
    "SECURE_PROXY_SSL_HEADER",
    "USE_X_FORWARDED_HOST",
    "USE_X_FORWARDED_PORT",
)

#: META keys of headers a proxy conventionally *appends* to rather than
#: overwrites (nginx ``$proxy_add_x_forwarded_for``, most cloud LBs). The
#: first element of an appended header is whatever the client sent.
_APPENDING_HEADERS = ("HTTP_X_FORWARDED_FOR",)


def _proxy_declarations(settings) -> list:
    """Which of _BEHIND_A_PROXY_SETTINGS this deployment has set."""
    declared = []
    for name in _BEHIND_A_PROXY_SETTINGS:
        if getattr(settings, name, None):
            declared.append(name)
    return declared


@checks.register("stapel_auth")
def check_proxy_trust_declared(app_configs=None, **kwargs):
    """W005 — behind a proxy with no declared client-IP header.

    Everything this module rate-limits, locks out or writes to an audit row
    is keyed by the caller's IP: the anonymous-mint budget
    (``ANONYMOUS_RATE_LIMIT_PER_HOUR``), the progressive OTP lockout, the
    ``LoginAttempt``/``AuthAuditLog``/``UserSession`` rows the security
    screen shows the user. That IP now comes from one place —
    ``stapel_core.netintel.client_ip`` — which trusts ``REMOTE_ADDR`` and
    nothing else until the deployment names a header.

    Behind a proxy with nothing named, ``REMOTE_ADDR`` is the proxy: every
    caller shares one budget, one lockout counter, and one address in the
    audit trail. That is the *safe* wrong answer (it over-restricts and
    never lies in the attacker's favour), but it is still wrong, and it is
    invisible — hence a check rather than silence. The unsafe wrong answer
    is what this pair used to do: read ``X-Forwarded-For`` by hand and
    believe its first element (audit F6).

    Only fires when the deployment has already declared, through a stock
    Django setting, that it sits behind a proxy — there is no reliable way
    to detect one otherwise, and guessing would make this noise.
    """
    from django.conf import settings

    declared = _proxy_declarations(settings)
    if not declared:
        return []

    from stapel_core.netintel.conf import netintel_settings

    if netintel_settings.TRUSTED_PROXY_HEADER:
        return []

    return [checks.Warning(
        f"This deployment declares it is behind a proxy ({', '.join(declared)}) "
        "but STAPEL_NETINTEL['TRUSTED_PROXY_HEADER'] is unset, so every "
        "request's client IP resolves to the proxy's own address. Rate "
        "limits, lockouts and audit/session IPs are all keyed on that value: "
        "they now collapse onto a single shared bucket.",
        hint="Have the edge proxy OVERWRITE a client-IP header on every "
             "request (nginx: proxy_set_header X-Real-IP $remote_addr) and "
             "point STAPEL_NETINTEL['TRUSTED_PROXY_HEADER'] at its META key "
             "(e.g. 'HTTP_X_REAL_IP'). Never point it at a header the edge "
             "only appends to — see stapel_auth.W006. If the proxy settings "
             "are inherited but this process is reached directly, silence "
             "this with SILENCED_SYSTEM_CHECKS.",
        id=W005_PROXY_TRUST_UNDECLARED,
    )]


@checks.register("stapel_auth")
def check_trusted_proxy_header_is_overwritten(app_configs=None, **kwargs):
    """W006 — the trusted client-IP header is one proxies usually append to.

    ``stapel_core.netintel.client_ip`` takes the FIRST element of the
    trusted header, which is correct only if the edge *replaces* the header
    on every request. The common nginx recipe
    ``proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`` appends
    instead, so the first element is the client's own text — and trusting it
    hands every attacker a fresh rate-limit budget, a clean lockout counter
    and a forged audit IP by rotating one header. That is the production
    defect this pair shipped as a hand-rolled read (audit F6); pointing the
    setting at ``X-Forwarded-For`` behind an appending proxy reintroduces it
    verbatim, one layer down.

    The library cannot see the proxy config, so this is a warning with a
    written-down escape: a deployment whose edge really does overwrite
    ``X-Forwarded-For`` silences it and thereby records that it checked.
    """
    from stapel_core.netintel.conf import netintel_settings

    header = netintel_settings.TRUSTED_PROXY_HEADER
    if not header or str(header).upper() not in _APPENDING_HEADERS:
        return []

    return [checks.Warning(
        f"STAPEL_NETINTEL['TRUSTED_PROXY_HEADER'] = {header!r}. The first "
        "element of this header is trusted as the client IP, but proxies "
        "conventionally APPEND to X-Forwarded-For (nginx "
        "$proxy_add_x_forwarded_for) rather than replace it — in which case "
        "that element is client-supplied and every IP-keyed rate limit, "
        "lockout and audit row is forgeable by rotating the header.",
        hint="Prefer a header the edge overwrites unconditionally (nginx: "
             "proxy_set_header X-Real-IP $remote_addr, then "
             "TRUSTED_PROXY_HEADER='HTTP_X_REAL_IP'). If your edge really "
             "does `proxy_set_header X-Forwarded-For $remote_addr` — "
             "overwrite, not append — and no other hop can prepend to it, "
             "record that by silencing stapel_auth.W006.",
        id=W006_APPENDING_PROXY_HEADER_TRUSTED,
    )]


__all__ += [
    "W005_PROXY_TRUST_UNDECLARED",
    "W006_APPENDING_PROXY_HEADER_TRUSTED",
    "check_proxy_trust_declared",
    "check_trusted_proxy_header_is_overwritten",
]
