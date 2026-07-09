# stapel-auth — MODULE.md

Agent-facing map of this module: what it provides, its fork-free extension points, and anti-patterns. Use it to classify a desired change as **app-layer override via an extension point** vs **upstream contribution** (see `docs/stdlib-contribution-pipeline.md` and system-design §8.6 in the stapel workspace). Stapel modules never import each other; all integration goes through `stapel_core` (comm, signals, registries) and Django settings. Everything below is verifiable against the code — file references are relative to this repo.

## What this module provides

Full-featured authentication as a single pip-installable Django app (`stapel_auth`, app label `authentication`):

- **Login/registration methods** (each gated by an `AUTH_*` flag): email/phone OTP, anonymous, password (+ optional TOTP step-up), OAuth2 (9 built-in providers), enterprise SSO (SAML SP + OIDC RP, per-org DB config), magic link, QR login, passkeys (WebAuthn), TOTP.
- **Sessions**: JWT (cookie + token pair), `UserSession` tracking, revoke one/all, suspicious-session detection and revocation, login notifications (new device / suspicious IP).
- **Step-up verification factors** (`otp_email`, `otp_phone`, `totp`, `passkey`) registered into the `stapel_core.verification` factor registry, plus the challenge endpoints (`/verification/...`) and per-user preferences backing the `auth.verification.policy` comm function.
- **Security surface**: audit log (`AuthAuditLog`), login attempt lockout, authenticator (email/phone) change flows — instant and delayed with day-1/7/13 notifications.
- **Admin/service API**: service API keys, capabilities, admin user broker, admin audit log; OpenID discovery + JWKS + token introspection; nginx `auth_request` monitoring proxy (`monitoring_proxy.py`).
- **GDPR provider** (`gdpr.py: AuthGDPRProvider`, section `auth`): export/delete of auth data; registered in-process in monolith mode, or run as a bus consumer (`manage.py consume_gdpr`) in microservices mode.
- **Flow registry** (`flows.py`): documented business flows consumed by `stapel_core.flows` tooling.

Public package API (`stapel_auth/__init__.py`, lazy `__all__`): `auth_settings`, `PROVIDER_REGISTRY`, the staff-role assignment services `assign_staff_role`, `revoke_staff_role`, `staff_roles_for` (admin-suite AS-2, see below), and the per-feature URL factories `get_admin_api_urls`, `get_anonymous_urls`, `get_magic_link_urls`, `get_mfa_urls`, `get_oauth_urls`, `get_openid_urls`, `get_otp_urls`, `get_password_urls`, `get_qr_urls`, `get_security_urls`, `get_sessions_urls`, `get_sso_urls`, `get_verification_urls`.

## Extension points (fork-free)

### Settings (`conf.py` — `STAPEL_AUTH = {...}` dict)

`auth_settings` is a `stapel_core.conf.AppSettings` namespace (the shared per-app settings pattern). Resolution order per key: `STAPEL_AUTH['KEY']` → flat Django setting of the same name → env var → built-in default. Env fallback is disabled (`no_env`) for secrets/trust anchors (`INTERNAL_SERVICE_KEY`, `OAUTH_PROVIDERS`), dotted-path seams (`OAUTH_PROVIDER_CLASSES`, `REREGISTRATION_MODEL`), `LEGACY_STEP_UP_GRANT_SCOPES`, `MOCK_OTP_CODE` and **every boolean gate** — env vars are strings and any non-empty string is truthy, so a stray `AUTH_PASSWORD_LOGIN=false` env var must not silently enable password login. All keys below exist in `conf.py: DEFAULTS`.

| Key | Default | What it customizes |
|---|---|---|
| `FRONTEND_URL` | `None` (env `FRONTEND_URL`) | Redirect base for SSO / magic link / QR login and the OAuth step-up `/totp-challenge` redirect; OAuth `redirect_after` validation. Unset ⇒ same-origin-relative redirects |
| `BACKEND_URL` | `None` (env `BACKEND_URL`) | Absolute backend URL for SAML/OIDC endpoints and revoke-suspicious links |
| `USE_MOCK_SMS_OTP` / `USE_MOCK_EMAIL_OTP` | `False` | Mock OTP delivery (dev/test) |
| `MOCK_OTP_CODE` | `'0000'` | The accepted code in mock mode |
| `OTP_TTL` | `600` | OTP code lifetime, seconds |
| `OTP_MAX_ATTEMPTS` | `5` | Wrong-code attempts before block |
| `OTP_RATE_LIMIT_PER_HOUR` | `3` | OTP send rate limit |
| `MAGIC_LINK_TTL` | `900` | Magic link lifetime, seconds |
| `MAGIC_LINK_RATE_LIMIT_PER_HOUR` | `3` | Magic link send rate limit |
| `QR_TOKEN_TTL` | `300` | QR login token lifetime, seconds |
| `SESSION_TTL_DAYS` | `30` | `UserSession` expiry |
| `ANONYMOUS_USER_LIFETIME_DAYS` | `30` | Anonymous account lifetime |
| `AUTH_ANONYMOUS` | `True` | Anonymous (guest) auth axis: gates `POST /anonymous/` (own URL factory `get_anonymous_urls`, independent of the email/phone gates) and the `anonymous` capability |
| `AUTH_TOTP` | `True` | TOTP axis: gates the `/totp/*` endpoints in `get_mfa_urls` (passkey-style) and the `mfa.totp` capability. Step-up rides `/totp/challenge/verify/` + `/totp/step-up/` — keep it on where step-up is on |
| `JWT_COOKIE_DOMAIN` | `None` (env) | JWT cookie domain override |
| `TOTP_ISSUER` | `'Stapel'` (env) | Issuer shown in authenticator apps |
| `WEBAUTHN_RP_ID` | `None` (env; falls back to request host) | Passkey relying-party ID |
| `WEBAUTHN_RP_NAME` | `'Stapel'` | Passkey relying-party display name |
| `WEBAUTHN_ORIGIN` | `None` (env; falls back to `FRONTEND_URL`) | Expected WebAuthn origin |
| `SSO_ENFORCED_REDIRECT_PATH` | `'/login'` | Redirect path when SSO is enforced for a domain |
| `LOGIN_NOTIFICATION_ENABLED` | `False` | New-device / suspicious-IP login alert emails |
| `REREGISTRATION_MODEL` | `'stapel_gdpr.models.ReRegistrationHash'` | **Dotted path**, resolved lazily in `gdpr.py` — stapel-gdpr is not a hard dependency; point at your own model |
| `INTERNAL_SERVICE_KEY` | `None` | Service-to-service auth key (`no_env` — set via `STAPEL_AUTH` or a flat setting, never picked up from the environment) |
| `OAUTH_PROVIDERS` | `{}` | Per-provider credentials: `{'google': {'client_id': ..., 'client_secret': ...}}` (parsed into `OAuthProviderConfig`) |
| `OAUTH_PROVIDER_CLASSES` | 9 built-ins (see below) | **Dotted-path list** of `OAuthProvider` subclasses registered at startup — append your own class to add a provider without touching this repo |
| `AUTH_PHONE_REGISTRATION` / `AUTH_EMAIL_REGISTRATION` / `AUTH_OAUTH_REGISTRATION` / `AUTH_SSO_REGISTRATION` | `True` | Registration method gates |
| `AUTH_PASSWORD_REGISTRATION` | `False` | Password registration gate |
| `AUTH_PHONE_LOGIN` / `AUTH_EMAIL_LOGIN` / `AUTH_OAUTH_LOGIN` / `AUTH_SSO_LOGIN` / `AUTH_QR_LOGIN` / `AUTH_PASSKEY_LOGIN` / `AUTH_MAGIC_LINK_LOGIN` | `True` | Login method gates |
| `AUTH_PASSWORD_LOGIN` | `False` | Password login gate |
| `OAUTH_STEP_UP` | `False` | TOTP challenge after OAuth login |
| `PASSWORD_LOGIN_STEP_UP` | `True` | TOTP challenge after password login |

The `AUTH_*` gates also drive the URL factories in `urls.py`: `include('stapel_auth.urls')` mounts everything (per-request 403 gating), or compose your own URLconf from `get_*_urls()` factories so disabled features 404.

The boolean gates above are this module's **config axes** (capability-config.md §1 in the stapel workspace root): machine-readable metadata over `STAPEL_AUTH`, published as the fourth contract artifact `docs/capabilities.json` (see below). Each factory declares its gating flags and contributed URL patterns in `urls.py: GATE_REGISTRY` via the `_gated()` helper — the declaration lives where the gating executes, so the artifact cannot drift from the code.

### Swappable models

| Model | Mechanism | Notes |
|---|---|---|
| User | Django's standard `AUTH_USER_MODEL` | stapel-auth references the user only via `settings.AUTH_USER_MODEL` / `get_user_model()`. Subclass `AbstractStapelUser` (stapel-core, `django/users/models.py`) in your app and point `AUTH_USER_MODEL` at it — expected fields: `email`, `phone`, `is_email_verified`, `is_phone_verified`, `auth_type`, `oauth_provider`, `oauth_id`, ... |
| Re-registration hash | `STAPEL_AUTH['REREGISTRATION_MODEL']` dotted path | Lazy import in `gdpr.py`; default targets stapel-gdpr but any model with a compatible interface works |

There are no `STAPEL_AUTH_*` swappable-model settings — all other models (`UserSession`, `TOTPDevice`, `PasskeyCredential`, `AuthAuditLog`, `Organization`, `SSOConfig`, `VerificationPreference`, ...) are concrete (`models.py`).

### OAuth providers (dotted paths)

Base class + registry live in `stapel_core.oauth` (`OAuthProvider`, `register_provider`, `_registry` re-exported here as `PROVIDER_REGISTRY`). Built-ins (`oauth_providers.py`, registered from `apps.py ready()` per `OAUTH_PROVIDER_CLASSES`): `google`, `github`, `zoom`, `facebook`, `apple`, `twitter`, `yandex`, `vk`, `sber` (+ `test` in `DEBUG`).

Add a provider without forking — subclass in your app and either append its dotted path to `STAPEL_AUTH['OAUTH_PROVIDER_CLASSES']` or call `register_provider(MyProvider())` from your own `AppConfig.ready()`. Credentials go in `STAPEL_AUTH['OAUTH_PROVIDERS'][<id>]`.

Enterprise SSO (SAML/OIDC) is configured **per organization in the database** (`Organization` / `SSOConfig` models, admin CRUD at `/sso/orgs/...`) — no code change or setting needed to onboard an IdP.

### Serializer seams

Every user-facing API view mixes in `SerializerSeamsMixin` (`utils.py`) and declares `<purpose>_request_serializer_class` / `<purpose>_response_serializer_class` class attributes; handler bodies only instantiate via the generated `get_<purpose>_serializer_class()` getters. To change a payload shape (extra fields, branding, validation), subclass the view, override the attribute (or getter), and mount your subclass via the URL factories:

```python
class MyMagicLinkViewSet(MagicLinkViewSet):
    response_serializer_class = MyResponseSerializer
```

Coverage: `otp/views.py` (AuthViewSet, AuthenticatorChangeViewSet), `password/views.py`, `mfa/views.py` (TOTPViewSet, PasskeyViewSet), `sessions/views.py`, `qr/views.py`, `magic_link/views.py`, `verification/views.py`. (Not yet seamed: `security/views.py`, `sso_views.py`, `admin/views.py`, `openid/views.py` — see anti-patterns / upstream.)

### Verification factors (step-up)

Mechanism (`@requires_verification`, challenge/grant stores) lives in `stapel_core.verification`; this module registers concrete factors at startup (`apps.py ready()` → `register_factor`, idempotent per id). Factors (`verification_factors.py`): `otp_email`, `otp_phone`, `totp`, `passkey` — interchangeable, any one closes a challenge. Endpoints (`urls.py: get_verification_urls`, always on): `GET /verification/<challenge_id>/`, `POST .../initiate/`, `POST .../complete/`, `GET|PUT /verification/preferences/`.

Host projects add factors **without touching this repo** via `STAPEL_VERIFICATION['EXTRA_FACTORS']` (dotted paths, stapel-core `verification/conf.py`) — same escape-hatch pattern as OAuth providers. Per-user opt-in/out is stored in `VerificationPreference` and served to core via the `auth.verification.policy` function.

#### Migrating off the legacy `/totp/step-up/` (DEPRECATED, removed in 1.0)

The one-time `X-Step-Up-Token` surface (`POST /totp/step-up/`,
`TOTPService.create_step_up`/`consume_step_up`, and the caller-raised
`error.403.step_up_required`) is deprecated in favour of the unified contract.
Migrate each sensitive action:

```python
# was: hand-rolled header check in your host code
if not TOTPService.consume_step_up(request.user, request.headers.get("X-Step-Up-Token")):
    return StapelErrorResponse(403, "error.403.step_up_required")

# now: declarative guard, envelope-driven client flow
@requires_verification(scope="sensitive", factors=["totp"], max_age=900)
def post(self, request): ...
```

Zero-downtime transit: a successful `/totp/step-up/` **also writes a server-side
verification grant** for `STAPEL_AUTH['LEGACY_STEP_UP_GRANT_SCOPES']` (default
`["sensitive"]`), so an already-deployed legacy frontend keeps passing the new
`@requires_verification` guards while you migrate the backend — no coordinated
frontend release required. Set `LEGACY_STEP_UP_GRANT_SCOPES = []` to disable the
bridge and issue the legacy token only. **Semantics differ**: the legacy token
is one-time, the bridged grant is reusable within `max_age` per scope (choose a
short `max_age` for strict one-shot behaviour). `@stapel/auth-react` is
envelope-only and needs no change. Remove `/totp/step-up/` usage before
upgrading to 1.0, where the legacy surface is deleted.

### Events & functions (comm surface)

Emitted events (`stapel_core.comm.emit`, transactional outbox; schemas in `schemas/emits/`):

| Event | Payload | When |
|---|---|---|
| `user.registered` | `{user_id, auth_type, email, avatar_url}` (`events.py: UserRegisteredPayload`) — `avatar_url` is `User.avatar` (OAuth only today), `null` otherwise | First successful auth of a new account (`otp/views.py: _notify_user_registered`) — profile/workspace creation is done by subscribers |
| `user.session_created` | `{user_id, session_id, device_type, ip_address, created_at}` | Schema declared; **no `emit()` call in code yet** (see gaps) |
| `user.session_revoked` | schema in `schemas/emits/` | Schema declared; **no `emit()` call in code yet** (see gaps) |
| `staff.role.assigned` | `{user_id, role, staff_roles, actor_id}` (`events.py: StaffRoleAssignedPayload`; `staff_roles` = full list **after** the change) | A staff role was assigned (`staff_roles.py: assign_staff_role` — admin, API, or direct service call). Audit stream for eventstore/notifications (admin-suite §3.8) |
| `staff.role.revoked` | `{user_id, role, staff_roles, actor_id}` (`events.py: StaffRoleRevokedPayload`) | A staff role was revoked (`staff_roles.py: revoke_staff_role`) |
| `notification.requested` | via `stapel_core.notifications.request_notification` | All outbound mail/SMS: types `otp_code`, `magic_link_login`, `new_device_login`, `suspicious_login`, `all_sessions_revoked`, `welcome`, `auth_change_requested` / `_reminder` / `_urgent` / `_completed`. Templates live in the notifications service — copy changes are **not** an auth fork |

Provided functions (`functions.py`, registered in `ready()`; schema in `schemas/functions/`):

| Function | Payload → Result | Consumer |
|---|---|---|
| `auth.verification.policy` | `{user_id}` → `{disabled_scopes, enabled_scopes}` | `stapel_core.verification.policy.get_user_policy` (cached core-side) |

Consumed events: `gdpr.export.requested`, `gdpr.delete.requested` — only in microservices mode, via `manage.py consume_gdpr` (`management/commands/consume_gdpr.py`, service name `auth`). stapel-auth calls no other module's functions.

### Staff roles — assignments + JWT transport (admin-suite AS-2)

Role **definitions** (name → clearance profile) are deploy config owned by
`stapel_core.access` (AS-1: `STAPEL_ACCESS["ROLES"]` merge-registry over the
builtins `viewer`/`editor`/`admin`). This module owns role **assignments**
(user → role names) and their transport. Invariant A2: the auth service is the
*single writer* — consumer services never grow an assignment table; they read
the claim.

**Model**: `StaffRoleAssignment` (`models.py`, table `staff_role_assignments`)
— `user` FK + `role_name` string (validated against the registry at write
time, deliberately NOT a FK into a DB catalog), unique per (user, role).
Declared `@access(view/add/change/delete = HIGH)`: with the AS-1 mandate
backends installed, only clearance-HIGH staff manage assignments (step-up on
HIGH operations arrives with AS-6). Targets must already be staff — assigning
a role to a non-staff account is refused (dormant-privilege guard).

**Write paths** (each emits its outbox audit event in the same transaction):

- Services: `stapel_auth.staff_roles.assign_staff_role(user, role, assigned_by=None)`
  / `revoke_staff_role(user, role, revoked_by=None)` (exported lazily from the
  package root).
- Django admin: `StaffRoleAssignmentAdmin` (immutable rows — change = revoke +
  assign; writes routed through the services so events are never skipped).
- API: `GET|POST /staff-roles/`, `DELETE /staff-roles/<assignment_id>/`
  (`admin/views.py: StaffRoleViewSet`) — staff + the corresponding
  `authentication.*_staffroleassignment` model permission (mandate/DAC/superuser).

**JWT claim contract** (`staff_roles.py: serialize_user_to_jwt_data` /
`create_tokens_for_user` — every token-issuance path in this module goes
through it):

```jsonc
{
  "user_id": "…", "is_staff": true, "is_superuser": false, …,
  "staff_roles": ["accountant", "editor"]   // staff/superuser tokens only
}
```

- **Staff tokens always carry the claim, an empty list included.** The empty
  list is authoritative ("zero roles") — it is what lets a revocation
  propagate to consumers under REPLACE sync-down (в.3). Sorted, so the claim
  is byte-stable across refreshes.
- **Non-staff tokens carry no claim** — same shape as pre-AS-2 tokens.
  Consumers treat a missing claim as "no information" and must not touch
  their local `staff_roles` copy (an old token can neither grant nor revoke).
- Role names unknown to a consumer's registry are ignored there
  (forward-compatible; admin-suite §3.3).
- Every refresh re-reads roles from the DB (`sessions/views.py:
  load_user_data`), so revocation latency ≤ access-token lifetime (A3);
  immediate revocation — the existing Redis user-blacklist.

**Sync-down (consumer side)** lives in stapel-core
(`get_or_create_user_from_jwt`): local `staff_roles` (and, per в.3,
`is_staff`/`is_superuser`) are REPLACED from the claim, and the validated
claim is stamped onto the request user as `_stapel_staff_roles_claim` so
`MandateBackend`'s claim source reads the *fresh token*, not a stale field.

**Auth-service mandate wiring** — on the auth service itself, point the AS-1
role-source seam at the assignment table (fresher than any claim; revocation
is effective on the next request):

```python
STAPEL_ACCESS = {
    "ROLE_SOURCES": [
        "stapel_auth.staff_roles.assignment_roles",   # auth DB is the truth
        "stapel_core.access.sources.claim_roles",
        "stapel_core.access.sources.group_roles",
    ],
}
```

### Admin categories — `@access` declarations (admin-suite AS-5)

Every model in `models.py` carries (or implicitly defaults to) a
`stapel_core.access.access` category — one declaration, consumed by admin
visibility, default staff rights, and the audit report (admin-suite §0).
Undecorated = `business` (visible, staff-manageable) and is the correct,
zero-effort default for domain tables; it is NOT restated on each of them.

- **`@access.ops`** (read-only journal, view=HIGH): `PhoneVerification`,
  `EmailVerification` (TTL-expiring OTP codes), `LoginAttempt`, `AuthAuditLog`
  (security/audit logs), `AuthenticatorChangeRequest` (change-flow workflow
  record — its `change_token` is additionally pinned via
  `AuthenticatorChangeRequestAdmin.secret_fields` since it is a live bearer
  credential for the pending change, not just workflow metadata).
- **`@access.secret`** (superuser-only, sensitive fields masked):
  `ServiceAPIKey` (`key`), `RefreshTokenTracker` (`token`) — both
  pattern-auto-detected; `TOTPDevice` (`secret`, `backup_codes` — the latter
  pinned explicitly via `secret_fields`, since "backup_codes" doesn't match
  the mask-pattern list); `SSOConfig` (`oidc_client_secret`,
  pattern-auto-detected — the SAML fields on the same model are IdP-supplied
  public config, not secrets).
- **Left `business`** (considered and rejected for ops/secret): `UserSession`
  (stores `jti`, not the raw refresh token — its own docstring: "storing jti
  (not raw token) is safe if DB is compromised" — and is user-facing device
  management, not a passive journal); `PasskeyCredential` (WebAuthn
  `public_key`/`credential_id` are public-by-design crypto material, not
  secrets, despite the model name); `Organization`, `OrgMembership`,
  `VerificationPreference` (ordinary domain tables). `StaffRoleAssignment`
  already carries its own full-form declaration (admin-suite AS-2, above).

`admin/__init__.py` registrations for the ops/secret models above (plus
`AuthAuditLog`, `TOTPDevice`, `SSOConfig`, which previously had none) inherit
`stapel_core.django.admin.base.StapelModelAdmin` so the category cosmetics
(read-only rendering, field masking) apply. Where a `ModelAdmin` already
listed a masked field in its own `readonly_fields` (e.g. `ServiceAPIKeyAdmin`
had `key`), that entry was removed — the mixin's masked placeholder and the
class's raw readonly field would otherwise both render, and the raw one
leaks the real value.

### Signals

| Signal | Sender/args | When |
|---|---|---|
| `stapel_core.signals.user_registered` | `sender=user.__class__, user, request` | Same milestone as the `user.registered` event, but in-process and synchronous — the extension point for host-app hooks in a monolith (`otp/views.py: _notify_user_registered`). Listener failures are logged, never raised |

### Flows (`flows.py`, autodiscovered by `stapel_core.flows`)

| Flow id | What it documents |
|---|---|
| `auth.passwordless_login` | Email OTP request → verify → `user.registered` on first login |
| `auth.password_login` | Password login (+ optional TOTP challenge via `PASSWORD_LOGIN_STEP_UP`) |
| `auth.step_up_verification` | **The reference flow** for the `stapel_core.verification` contract (403 envelope → info → initiate → complete → retry; preferences) |

Flow texts are i18n-keyed (flow-system.md §2; this module is the reference
migration): the `flows.py` literals are the canonical **English** source
texts with implicit keys (`flow.<id>.title` / `flow.<id>.step.<order>.note`),
and `translations/flows.en.json` / `translations/flows.ru.json` are the
committed catalogs `stapel_core.flows.i18n.resolve_flow_texts` picks up.
Drift gates in `tests/test_flow_i18n.py`: en catalog == literals, ru covers
the same key set. To localize into another language, ship (or generate via
`generate_flow_docs --lang X --llm`) another `flows.<lang>.json` — no fork,
the catalogs merge over INSTALLED_APPS.

**SA-document trees** (flow-system.md §4): `docs/flows/{en,ru}/` are the
rendered SA-documents (mermaid step diagram, steps, endpoint table with the
step-up verification contract), generated by `generate_project_docs` and
linked from the README ([Flows (EN)](docs/flows/en/README.md) · [Флоу
(RU)](docs/flows/ru/README.md)). `tests/test_flow_docs.py` is the release-gate
drift check: it regenerates into a temp dir and asserts byte-for-byte equality
with the committed tree. Regenerate after changing a flow or catalog with
`STAPEL_REGEN_FLOW_DOCS=1 pytest tests/test_flow_docs.py` and commit
`docs/flows/`.

**Error registry artifact** (error-remediation): `errors.py` declares each key's
en text and machine-readable `remediation` via
`register_service_errors(AUTH_ERRORS, remediation=AUTH_REMEDIATION)`.
`docs/errors.json` is the committed codegen artifact (the array of `{code,
status, params, remediation, en}` the frontend error bundle is generated from),
emitted by core's `generate_error_keys` and covering auth's keys plus the
cross-cutting `verification`/`captcha` keys. `tests/test_error_keys.py` is the
drift gate — regenerate with `STAPEL_REGEN_ERROR_KEYS=1 pytest
tests/test_error_keys.py` and commit `docs/errors.json`.

**Error localization** (i18n-shipping.md §5): `errors.json` stays the en canon;
ru ships as a flat `translations/errors.ru.json` catalog with a
`translations/.state.json` provenance sidecar, and human-readable references
[Errors (EN)](docs/errors.en.md) · [Ошибки (RU)](docs/errors.ru.md). Semantics of
the i18n seams (library-standard §3.3 — MODULE.md states the merge semantics of
each key): the **error registry** is `dict.update`/**last-wins** (a host
`errors.py` autodiscovered after ours overrides an en text — and its raise-time
render — without a fork); the **locale catalogs** are discovered over
INSTALLED_APPS and merged **later-wins** (a host app's
`translations/errors.<lang>.json` overrides our texts, and an override MUST keep
the canon's `{param}` slots — gated). ru provenance is honest: 112 keys seeded
from the curated `stapel-translate` builtin fixtures (`origin: seed:stapel-builtin`,
no tokens spent), 4 auth-only keys machine-translated (`origin: llm`, unreviewed —
the gate's W-counter, cleared by `translate_catalogs --approve`). Gate +
regenerate: `tests/test_error_i18n.py` (`check_translation_catalogs` — E on
missing/stale/params/byte-instability); regenerate with
`STAPEL_REGEN_ERROR_I18N=1 pytest tests/test_error_i18n.py::test_regen` and commit
`translations/errors.ru.json`, `translations/.state.json`, `docs/errors.{en,ru}.md`.

### Config axes + `capabilities.json` — the fourth contract artifact (ETALON)

`docs/capabilities.json` describes this module's **config axes** — machine-readable
metadata over the `STAPEL_AUTH` gates (design: `docs/capability-config.md` in the
stapel workspace root, §1-§2). It rides the same pipeline as the triad below:
emitted by `make contract`, drift-gated by `make contract-check` and
`tests/test_contract.py`, committed.

Derivable facts are derived, semantics are curated:

- **Derived** (`_capabilities.py`): axis `key`/`kind`/`default`/`group` from
  `conf.py: DEFAULTS` (include rule, documented there: a key is an axis iff it
  starts with `AUTH_` or ends with `_STEP_UP` — 13 method gates + anonymous +
  totp + 2 step-up policies = 17 axes; TTLs/rate-limits/credentials are tuning
  knobs, not axes). `gates.operations` come from `urls.py: GATE_REGISTRY` —
  every URL factory declares `(name, flags, patterns)` through `_gated()` where
  the gating executes — cross-referenced against `docs/schema.json`
  operationIds. Flags on one factory compose with **OR** (`gates.co_gates`
  lists the siblings): the block 404s only when all of them are off.
- **Curated** (`docs/capabilities.meta.json`, hand-written): per-axis
  `business_label` + `summary` in business language, module `provides`,
  `requires[]`, `extension_points[]`, optional `behavior` for axes that gate
  behavior rather than endpoints (the step-up pair). A missing or stale meta
  entry is a **loud emission error**, so the curated layer cannot silently
  desync from the code.

Consumers: the studio CTO capability index aggregates these manifests
shelf-wide; humans and third-party agents get a config surface they can read
without opening `conf.py`. Runtime truth for frontends remains
`GET /auth/api/capabilities/`. The emitter is a local prototype — the mechanism
moves to stapel-tools for the shelf sweep (capability-config.md §5-A6), with
only `capabilities.meta.json` staying per-module.

### Contract emission — the `schema` + `flows` + `errors` triad (ETALON)

This module emits its **own** machine-readable API contract, per-module, so the
frontend codegen reads a committed, version-pinned artifact instead of checking
out the monolith aggregate at floating `main` (contract-pipeline.md §2, verdict
**A**: contract = a reviewable commit, like `docs/errors.json` always was). The
triad lives in `docs/`:

```
docs/schema.json   drf-spectacular OpenAPI, this module only, canonical /auth/api/ prefix
docs/flows.json    generate_flow_docs machine artifact, canonical-prefix endpoint paths
docs/errors.json   generate_error_keys registry (the original per-module etalon)
```

The emitted `schema.json` + `flows.json` are **byte-identical to the monolith
aggregate's auth slice** — the paths under `/auth/api/` plus the transitive
`$ref` component closure they reference. That identity is what lets the frontend
repoint from the aggregate to per-module sources with a zero-diff `gen:check`.
`tests/test_contract.py::test_matches_monolith_auth_slice` asserts it in the
workspace (skipped in module CI, where the monolith isn't checked out).

**Harness** (three ~30-line files, plus the shared mechanism in `stapel_tools.codegen`):
- `_codegen_settings.py` — the single `settings.configure(**kwargs)` block, shared
  with `conftest.py` so the test instance and the codegen instance can never drift.
  `contract=True` swaps in the production `REST_FRAMEWORK` (DRF caches it on first
  access, so it must be right at configure time).
- `codegen_urls.py` — mounts `stapel_auth.urls` (+ `stapel_gdpr.urls`, exactly as
  the monolith does) at the canonical `auth/api/` prefix. **This is the
  make-or-break**: without it the emitted paths are bare (`/password/login/`) and
  the operationIds collapse — with it they match the aggregate byte-for-byte.
- `_codegen.py` — configures the instance on `codegen_urls`, then forces
  `spectacular_settings.SCHEMA_PATH_PREFIX = "/"` on the drf-spectacular singleton
  (see below) and calls the shared `emit_schema` / `emit_flows` / `emit_errors`.

**Gate:** `make contract` re-emits; `make contract-check` regenerates into a temp
dir and diffs — identical discipline to `test_error_keys` / `test_flow_docs`. The
CI-enforced gate is `tests/test_contract.py` (pytest, run in the module's venv).
Regenerate after any serializer/view/url/flow/error change:

    make contract        # emits the triad AND capabilities.json

then commit `docs/{schema,flows,errors,capabilities}.json`.

**Two non-obvious facts the emission depends on** (they bit auth-first and will
bite the copies, so they are the reason this is the etalon):
1. **`SCHEMA_PATH_PREFIX` must be pinned to `"/"`.** drf-spectacular derives
   operationIds by stripping the *common path prefix of all endpoints*. The
   monolith spans every module, so that prefix is `/` and operationIds keep the
   mount (`auth_api_anonymous_create`). A single-module harness sees only
   `/auth/api/*`, so it would strip that and collapse to `anonymous_create`.
   Pinning `SCHEMA_PATH_PREFIX="/"` reproduces the aggregate. `SCHEMA_PATH_PREFIX_TRIM`
   stays `False`, so the path *keys* keep `/auth/api/`.
2. **drf-spectacular ignores Django `SPECTACULAR_SETTINGS` here.** It snapshots its
   settings singleton at *import* time, before a `configure()`-based harness can
   populate it — so it (and the monolith, identically) emits on drf **defaults**
   (`info.title=""`, no `bearerAuth`, no `x-stapel-*` extensions). Do **not**
   "fix" this by applying `get_spectacular_settings` to the singleton: that would
   add title/hooks the monolith slice doesn't have and *break* byte-identity. The
   only override is `SCHEMA_PATH_PREFIX`, patched on the singleton after setup.

**Adding contract emission to another pair-backend** (notifications / profiles /
billing / workspaces — copy this module, 4 steps):
1. Extract the `conftest.py` `settings.configure` body into
   `_codegen_settings.py::settings_kwargs(root_urlconf, contract)`; have conftest
   call it (no behavior change). Add `drf_spectacular` to `INSTALLED_APPS` and the
   production `REST_FRAMEWORK` under `contract=True` (auth already had both).
2. Add `codegen_urls.py` mounting the module (+ any sibling the monolith co-mounts
   under the same service prefix) at the module's canonical `<mod>/api/` prefix —
   copy it from the monolith's `urls.py`, exactly.
3. Add `_codegen.py` (copy verbatim; change only the urlconf module name) — it
   pins `SCHEMA_PATH_PREFIX="/"` and calls the shared emitters. Add the `Makefile`
   `contract` / `contract-check` targets and `tests/test_contract.py`.
4. Run `make contract`, then verify byte-identity against the monolith slice
   (`test_matches_monolith_auth_slice`, retargeted to `/<mod>/api/`). **If it is
   not zero-diff, report the exact delta — do not hand-tune the artifact.** Modules
   with no `@flow_step` emit `flows.json = []` (valid). Confirm the schema's
   component closure is self-contained; a module that `$ref`s a sibling-only
   component (e.g. profiles↔auth user linkage) needs that sibling installed in its
   harness (contract-pipeline.md §9 Q2).

## Anti-patterns

- **Never import another stapel module** (`stapel_gdpr`, `stapel_notifications`, `stapel_workspaces`, ...) from code that extends or configures auth. Integration is only via `stapel_core` comm (events/functions), signals, registries, and dotted-path settings. Even the GDPR model dependency here is a lazy dotted path, not an import.
- **Don't monkey-patch views or serializers.** Subclass the view, override the `*_serializer_class` seam, and mount your subclass through the `get_*_urls()` factories (or your own `path()` entries). Handler bodies go through `get_<purpose>_serializer_class()` precisely so overrides are picked up everywhere.
- **Don't fork for branding/copy.** Email/SMS wording lives in notification templates (the module only emits `notification.requested` with a `notification_type` + variables); TOTP/passkey product names are `TOTP_ISSUER` / `WEBAUTHN_RP_NAME` settings; response shapes are serializer seams.
- **Don't add fields by editing models here.** Extra user fields go on your `AUTH_USER_MODEL` subclass of `AbstractStapelUser`. Auth-owned tables (sessions, audit log, ...) are upstream property — if they genuinely need a column, that is a contribution.
- **Don't hardcode a new OAuth provider or verification factor into this repo's registries.** Register from your app via `OAUTH_PROVIDER_CLASSES` / `register_provider()` and `STAPEL_VERIFICATION['EXTRA_FACTORS']` / `register_factor()`.
- **Don't bypass the feature gates.** To disable a method, flip its `AUTH_*` flag (and/or omit its URL factory); don't strip URLs from a vendored copy.
- **Don't consume `PROVIDER_REGISTRY` mutation as an API.** It is exposed for tests; the supported mutation path is `register_provider` / settings.
- **Don't reference the concrete user class.** Always `get_user_model()` / `settings.AUTH_USER_MODEL` (the module itself follows this rule everywhere).

## App-layer override vs upstream contribution — rule of thumb

**App-layer** (stays in your project, your property): anything expressible through the tables above — a settings value or feature flag, a new OAuth provider class, a new verification factor, a swapped serializer on a subclassed view, a custom user model, a `user_registered` signal receiver or `user.registered` subscriber, notification template copy, a custom `REREGISTRATION_MODEL`, your own URLconf composition. Test: *does the change fit an existing seam without editing files in `stapel_auth/`?* If yes — it is an override, never a fork.

**Upstream contribution** (belongs in this repo, via the contribution pipeline — `contrib_open`, review origin, PyPI release): bug fixes; schema changes to auth-owned models/migrations; new endpoints or flows; a *missing seam* (e.g. serializer seams for `security/`, `sso_views.py`, `admin/`, `openid/` views; actually emitting the declared `user.session_created` / `user.session_revoked` events; a new generic setting). Test: *is the change generic — would other Stapel hosts want it, and does it require editing this repo?* If yes — contribute upstream; while the release is pending, consume the beta via the artifact channel, never a long-lived fork.

**Neither** (client-specific, un-mergeable): keep it in your app layer as an override built on the nearest seam; if no seam exists, the upstream contribution is *adding the seam*, and the specific behavior stays yours.
