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


PROVISION_USER_SCHEMA = {
    "type": "object",
    "properties": {
        "username": {
            "type": "string",
            "description": "Full namespaced login 'org_slug/local' — exactly "
            "one '/', both sides in the stock username alphabet.",
        },
        "password": {
            "type": ["string", "null"],
            "description": "Initial password chosen by the provisioning "
            "admin. Omitted/null: the server generates a crypto-strong "
            "password and returns it once as generated_password.",
        },
        "email": {
            "type": ["string", "null"],
            "description": "Normally null — org-provisioned accounts have no "
            "email anchor (spec C1). A non-null value is stored UNVERIFIED.",
        },
        "display_name": {
            "type": ["string", "null"],
            "description": "Display-name hint: mirrored into first_name and "
            "forwarded on the user.registered event for downstream consumers "
            "(e.g. profiles).",
        },
        "first_login_policy": {
            "type": "string",
            "enum": ["password_change", "mfa_enroll"],
            "description": "Which first-login flag to raise: "
            "password_change_required or mfa_enrollment_required (spec C2).",
        },
    },
    "required": ["username", "first_login_policy"],
    "additionalProperties": False,
}


MFA_STATUS_SCHEMA = {
    "type": "object",
    "properties": {
        "user_id": {
            "type": "string",
            "description": "Primary key of the user whose MFA status is resolved.",
        },
    },
    "required": ["user_id"],
    "additionalProperties": False,
}


@function("auth.provision_user", schema=PROVISION_USER_SCHEMA)
def provision_user(payload: dict) -> dict:
    """Create an org-provisioned login/password user (org-program §C1).

    Payload: ``{"username", "password"?, "email"?, "display_name"?,
    "first_login_policy"}``. Success: ``{"user_id", "generated_password"?}``
    — ``generated_password`` is present only when the caller omitted
    ``password`` and is returned exactly ONCE; it is never logged and never
    rides any event/outbox payload (privacy canon of login grants applies:
    credential material never reaches log lines).

    Structured failures (canonical error keys, so the HTTP caller can pass
    them straight to a StapelErrorResponse) instead of raising:

    * ``{"error": "error.400.username_namespace_invalid"}`` — username is
      not a valid ``org_slug/local`` namespaced login;
    * ``{"error": "error.409.username_taken"}`` — the full username exists;
    * ``{"error": "error.400.bad_request"}`` — a caller-provided password
      fails the deployment's password canon (Django validators). The
      server-generated password path cannot fail this way.

    The created account: ``auth_type="login"``, no email anchor by default,
    the ``first_login_policy`` flag raised (password login then returns the
    forced-change / mfa-enroll intermediate instead of a session — spec C2),
    and a ``user.registered`` emit for downstream consumers (profiles et
    al.) carrying the ``display_name`` hint.
    """
    import secrets

    from django.contrib.auth import get_user_model
    from django.contrib.auth.password_validation import validate_password
    from django.core.exceptions import ValidationError
    from django.db import IntegrityError, transaction

    from stapel_auth.errors import (
        ERR_400_USERNAME_NAMESPACE_INVALID,
        ERR_409_USERNAME_TAKEN,
    )
    from stapel_auth.utils import parse_namespaced_login, validate_local_username

    username = payload["username"]
    try:
        org_slug, local = parse_namespaced_login(username)
    except ValueError:
        return {"error": ERR_400_USERNAME_NAMESPACE_INVALID}
    if org_slug is None or not validate_local_username(local) \
            or not validate_local_username(org_slug):
        # Provisioned logins are ALWAYS namespaced — a bare username would
        # let an org squat the global username space (spec C1).
        return {"error": ERR_400_USERNAME_NAMESPACE_INVALID}

    User = get_user_model()
    if User.objects.filter(username=username).exists():
        return {"error": ERR_409_USERNAME_TAKEN}

    password = payload.get("password") or None
    generated = None
    if password is None:
        # Crypto-strong server-side password (~128 bits). Returned once in
        # the result below and NEVER logged.
        generated = secrets.token_urlsafe(16)
        password = generated
    else:
        try:
            validate_password(password)
        except ValidationError:
            from stapel_core.django.api.errors import ERR_400_BAD_REQUEST

            return {"error": ERR_400_BAD_REQUEST}

    display_name = payload.get("display_name") or None
    policy = payload["first_login_policy"]
    try:
        with transaction.atomic():
            user = User.objects.create(
                username=username,
                email=payload.get("email") or None,
                auth_type="login",
                first_name=(display_name or "")[:150],
                password_change_required=(policy == "password_change"),
                mfa_enrollment_required=(policy == "mfa_enroll"),
            )
            user.set_password(password)
            user.save(update_fields=["password"])
    except IntegrityError:
        # Lost the race on the unique username — same structured failure.
        return {"error": ERR_409_USERNAME_TAKEN}

    from stapel_auth.otp.views import _notify_user_registered

    _notify_user_registered(user, display_name=display_name)

    result = {"user_id": str(user.pk)}
    if generated is not None:
        result["generated_password"] = generated
    return result


@function("auth.mfa_status", schema=MFA_STATUS_SCHEMA)
def mfa_status(payload: dict) -> dict:
    """Per-user MFA status (org-program §C2/C3).

    Payload: ``{"user_id": "<pk>"}``. Returns ``{"has_strong_mfa": bool,
    "factors": [{"id", "strength"}, ...]}`` — the registered verification
    factors the user can actually complete, annotated with the strength
    canon (totp/passkey/otp_phone strong; a bare email code is weak and
    never counts as 2FA). Unknown users get ``{False, []}`` — same
    "absence means defaults" contract as ``auth.verification.policy``.

    Consumed by workspaces' require_mfa enforcement (sync sweep when the
    policy flips on) alongside the ``user.mfa_enabled|disabled`` events.
    """
    from django.contrib.auth import get_user_model
    from django.core.exceptions import ValidationError

    from stapel_core.verification import factor_registry, strong_factors

    User = get_user_model()
    try:
        user = User.objects.filter(pk=payload["user_id"]).first()
    except (ValidationError, ValueError):
        user = None
    if user is None:
        return {"has_strong_mfa": False, "factors": []}

    factors = [
        entry for entry in factor_registry.describe()
        if factor_registry.get(entry["id"]).available_for(user)
    ]
    return {
        "has_strong_mfa": bool(strong_factors(user)),
        "factors": factors,
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
