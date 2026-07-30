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
        "first_login_policies": {
            "type": "array",
            "items": {"type": "string", "enum": ["password_change", "mfa_enroll"]},
            "uniqueItems": True,
            "description": "Which first-login steps the org demands before "
            "this account gets a session. INDEPENDENT, not alternatives "
            "(#90): password_change raises password_change_required, "
            "mfa_enroll raises mfa_enrollment_required, and both together "
            "are a legal and common ask. [] means no first-login step.",
        },
        "first_login_policy": {
            "type": "string",
            "enum": ["password_change", "mfa_enroll"],
            "description": "DEPRECATED (#90) — the single-policy spelling, "
            "kept so callers pinned to stapel-workspaces < 0.13 keep "
            "working. Read only when first_login_policies is absent, and "
            "then as a one-element set. Use first_login_policies.",
        },
    },
    "required": ["username"],
    "additionalProperties": False,
}


APPLY_FIRST_LOGIN_POLICIES_SCHEMA = {
    "type": "object",
    "properties": {
        "user_id": {
            "type": "string",
            "description": "Primary key of the account to raise the policies on.",
        },
        "policies": {
            "type": "array",
            "items": {"type": "string", "enum": ["password_change", "mfa_enroll"]},
            "uniqueItems": True,
            "description": "First-login steps to demand. ADDITIVE — a "
            "policy already outstanding stays outstanding, and a policy "
            "NOT listed is never lowered.",
        },
    },
    "required": ["user_id", "policies"],
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


def _resolve_first_login_policies(payload: dict) -> list[str] | None:
    """The policy set a provisioning payload asks for, or ``None`` if invalid.

    Reads the plural key; falls back to the deprecated singular one as a
    one-element set. Neither key present is invalid rather than empty —
    "no first-login step" is a decision an org makes by sending
    ``"first_login_policies": []``, not something a mistyped key should
    arrive at by accident.
    """
    from stapel_auth.password.services import FirstLoginPolicyService

    if "first_login_policies" in payload:
        return FirstLoginPolicyService.normalize_policies(
            payload["first_login_policies"]
        )
    legacy = payload.get("first_login_policy")
    if legacy is None:
        return None
    return FirstLoginPolicyService.normalize_policies([legacy])


@function("auth.provision_user", schema=PROVISION_USER_SCHEMA)
def provision_user(payload: dict) -> dict:
    """Create an org-provisioned login/password user (org-program §C1).

    Payload: ``{"username", "password"?, "email"?, "display_name"?,
    "first_login_policies"}``. Success: ``{"user_id",
    "generated_password"?}`` — ``generated_password`` is present only when
    the caller omitted ``password`` and is returned exactly ONCE; it is
    never logged and never rides any event/outbox payload (privacy canon of
    login grants applies: credential material never reaches log lines).

    **The policies are a SET, and the members are independent (#90).** This
    function used to take one ``first_login_policy`` string, and the
    creation spelled it ``password_change_required=(policy ==
    "password_change"), mfa_enrollment_required=(policy == "mfa_enroll")``
    — so asking for either demand actively cleared the other. An org could
    not require a password rotation AND a second factor, although the user
    row has carried two independent booleans since Wave 0 and the login
    flow has always chained them (forced change → mfa enrol). The
    limitation lived entirely in this payload; the checkboxes in the invite
    modal were inert because of this line.

    ``first_login_policy`` (singular) is still read when
    ``first_login_policies`` is absent, as a one-element set, so a caller
    pinned to stapel-workspaces < 0.13 keeps working. Neither key present
    is a **failure**, not a silently empty set: omitting the policies by
    typo must not quietly provision an account with no first-login step at
    all. ``"first_login_policies": []`` is how a caller says "none" on
    purpose.

    Structured failures (canonical error keys, so the HTTP caller can pass
    them straight to a StapelErrorResponse) instead of raising:

    * ``{"error": "error.400.username_namespace_invalid"}`` — username is
      not a valid ``org_slug/local`` namespaced login;
    * ``{"error": "error.409.username_taken"}`` — the full username exists;
    * ``{"error": "error.400.bad_request"}`` — a caller-provided password
      fails the deployment's password canon (Django validators), or the
      policy set is missing/malformed. The server-generated password path
      cannot fail this way.

    The created account: ``auth_type="login"``, no email anchor by default,
    every demanded first-login flag raised (a session on ANY of the 19
    issuance paths then returns the forced-change / mfa-enrol intermediate
    instead — ``sessions/guard.py``, 0.15.0), and a ``user.registered``
    emit for downstream consumers (profiles et al.) carrying the
    ``display_name`` hint.
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
    from stapel_auth.password.services import FirstLoginPolicyService
    from stapel_auth.utils import parse_namespaced_login, validate_local_username

    policies = _resolve_first_login_policies(payload)
    if policies is None:
        from stapel_core.django.api.errors import ERR_400_BAD_REQUEST

        return {"error": ERR_400_BAD_REQUEST}

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
    try:
        with transaction.atomic():
            user = User.objects.create(
                username=username,
                email=payload.get("email") or None,
                auth_type="login",
                first_name=(display_name or "")[:150],
                # Every flag named, raised or not: listing only the True
                # ones would leave the rest at whatever the model default
                # happens to be, which is how "setting one clears the
                # other" survives a refactor unnoticed.
                **FirstLoginPolicyService.flag_kwargs(policies),
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


@function(
    "auth.apply_first_login_policies", schema=APPLY_FIRST_LOGIN_POLICIES_SCHEMA
)
def apply_first_login_policies(payload: dict) -> dict:
    """Raise first-login policies on an existing account (#90).

    Payload: ``{"user_id", "policies": [...]}``. Returns
    ``{"applied": [...]}`` — the policies this call actually raised, which
    is a subset of what was asked: one already outstanding is not raised
    twice, and ``mfa_enroll`` against an account that already carries a
    strong factor is a demand with nothing left to do.

    **Additive, never subtractive.** A policy not in the list is left
    exactly as it was. The flags are per-ACCOUNT while the callers are
    per-ORG (workspaces applies its ``provisioned_user_policies`` when an
    invitation is accepted), so a subtractive contract would let one tenant
    lower another tenant's bar — or lower a bar the user's own security
    settings put up. Only completing the step clears a flag.

    The other side of that coin is a real, deliberate limitation worth
    naming: the flags live on the user, not on the membership. An account
    that joins org A with ``mfa_enroll`` is blocked from EVERY login,
    including into org B, until it enrols. That is the honest reading of a
    per-account credential precondition, and it is why this seam is called
    only when an org has actually configured a policy.

    Unknown user → ``{"error": "error.404.not_found"}`` (the core generic
    key): this function is only ever called by a service that already
    resolved the account, so an unknown id is a wiring bug and must be
    loud, not a silent no-op that leaves the caller believing the policy
    landed. Deliberately NOT the "absence means defaults" contract of
    ``auth.verification.policy`` / ``auth.mfa_status``, which answer
    questions; this one makes a change and must say whether it happened.
    """
    from django.contrib.auth import get_user_model
    from django.core.exceptions import ValidationError
    from stapel_core.django.api.errors import ERR_404_NOT_FOUND

    from stapel_auth.password.services import FirstLoginPolicyService

    policies = FirstLoginPolicyService.normalize_policies(payload["policies"])
    if policies is None:
        from stapel_core.django.api.errors import ERR_400_BAD_REQUEST

        return {"error": ERR_400_BAD_REQUEST}

    User = get_user_model()
    try:
        user = User.objects.filter(pk=payload["user_id"]).first()
    except (ValidationError, ValueError):
        user = None
    if user is None:
        return {"error": ERR_404_NOT_FOUND}

    return {"applied": FirstLoginPolicyService.apply(user, policies)}


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
