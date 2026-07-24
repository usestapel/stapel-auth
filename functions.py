"""comm Function providers of the auth service.

Registered from ``StapelAuthConfig.ready()`` (importing this module is
enough: re-imports are no-ops and re-registering the same handler object is
idempotent). Other modules call these by name via ``stapel_core.comm.call``
— no import of this package needed:

    from stapel_core.comm import call

    call("auth.verification.policy", {"user_id": "42"})
"""
import logging

from stapel_core.comm import function

logger = logging.getLogger(__name__)

VERIFICATION_POLICY_SCHEMA = {
    "type": "object",
    "properties": {
        "user_id": {
            "type": "string",
            "description": "Primary key of the user whose policy is resolved.",
        },
    },
    "required": ["user_id"],
    "additionalProperties": False,
}


ISSUE_LOGIN_GRANT_SCHEMA = {
    "type": "object",
    "properties": {
        "email": {
            "type": "string",
            "description": "Email address the grant is bound to (case-insensitive).",
        },
        "verified_email": {
            "type": "boolean",
            "description": "Whether the issuer has proven mailbox ownership "
            "(e.g. the invite email was delivered there). Sets "
            "is_email_verified on a created account. Default true.",
        },
        "create_if_missing": {
            "type": "boolean",
            "description": "Create a user (auth_type=email, unusable password) "
            "on exchange when no account exists for the email. Default false.",
        },
        "language": {
            "type": ["string", "null"],
            "description": "Optional UI language hint for a created account, "
            "forwarded on the user.registered event for downstream consumers "
            "(e.g. profiles).",
        },
    },
    "required": ["email"],
    "additionalProperties": False,
}


@function("auth.issue_login_grant", schema=ISSUE_LOGIN_GRANT_SCHEMA)
def issue_login_grant(payload: dict) -> dict:
    """Mint a single-use login grant token (workspaces-org-program §B3).

    Payload: ``{"email", "verified_email"?, "create_if_missing"?,
    "language"?}``. Returns ``{"grant_token": "<token>"}`` — a cache-stored,
    15-minute, single-use token the holder exchanges for a JWT session at
    ``POST /grant/exchange/`` (mounted only when ``AUTH_LOGIN_GRANT`` is on).

    The user is resolved/created on EXCHANGE, not here — see
    ``stapel_auth.login_grant.services.LoginGrantService.exchange``.

    Canonical caller: the workspaces invitation claim endpoint
    (``POST invitations/<token>/claim``) for not-yet-registered emails.

    Privacy: the returned token is a credential — callers must never log it,
    and especially never together with the email.
    """
    from .login_grant.services import LoginGrantService

    token = LoginGrantService.issue(
        email=payload["email"],
        verified_email=payload.get("verified_email", True),
        create_if_missing=payload.get("create_if_missing", False),
        language=payload.get("language"),
    )
    return {"grant_token": token}


@function("auth.verification.policy", schema=VERIFICATION_POLICY_SCHEMA)
def verification_policy(payload: dict) -> dict:
    """Per-user step-up verification policy.

    Payload: ``{"user_id": "<pk>"}``. Returns
    ``{"disabled_scopes": [...], "enabled_scopes": [...]}`` — the scopes the
    user explicitly turned off (``default_on`` endpoints) or on (``opt_in``
    endpoints). Unknown users simply have empty lists: absence of
    preferences means framework defaults apply.

    Consumed by ``stapel_core.verification.policy.get_user_policy`` (cached
    core-side for ``POLICY_CACHE_TTL`` seconds).
    """
    from .models import VerificationPreference

    disabled: list[str] = []
    enabled: list[str] = []
    rows = VerificationPreference.objects.filter(
        user_id=payload["user_id"]
    ).values_list("scope", "enabled")
    for scope, is_enabled in rows:
        (enabled if is_enabled else disabled).append(scope)
    return {"disabled_scopes": sorted(disabled), "enabled_scopes": sorted(enabled)}
