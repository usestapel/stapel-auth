# Changelog

## [Unreleased]

## [0.7.1] — 2026-07-17

Fleet follow-up to stapel-core 0.12.0 (legacy shim sweep). No source changes
were needed — `stapel-auth` already imports the canonical
`stapel_core.django.jwt.*` paths, not the removed `django.{utils,jwt_provider,
authentication}` shims. Full suite green against core 0.12.0.

### Changed
- `stapel-core` dependency ceiling `<0.12` → `<0.13`.

## [0.7.0] — 2026-07-17

Legacy scrub (owner directive: only current code, no back-compat shims).
Removals of public surface ⇒ minor bump per house semver.

### Removed — legacy X-Step-Up-Token surface (was deprecated, slated for 1.0)
- `POST /totp/step-up/` endpoint (`totp_step_up`), `TOTPService.create_step_up`
  / `consume_step_up` / `_issue_step_up_token` / `STEP_UP_TTL`, the
  `TOTPStepUpSerializer` / `TOTPStepUpResponseSerializer` / `TOTPStepUpResponse`
  contract types, the `LEGACY_STEP_UP_GRANT_SCOPES` setting (server-side grant
  bridge) and the `error.403.step_up_required` key. The unified step-up
  contract (`@requires_verification` + the `/verification/` envelope flow) is
  the only mechanism now. `AuthEventType.TOTP_STEP_UP` audit choice dropped
  (migration 0016); MODULE.md migration recipe deleted.

### Removed — backward-compatibility shim modules
- `stapel_auth.services`, `stapel_auth.serializers`, `stapel_auth.views`,
  `stapel_auth.otp.utils` — pure re-export shims deleted; import from the
  owning sub-packages (`sessions/`, `otp/`, `oauth/`, `security/`,
  `password/`, `mfa/`, `magic_link/`). `stapel_auth.dto` keeps only the
  cross-cutting `SimpleStatusResponse`; sub-package DTOs import from their
  home modules. Root `UserSerializer` duplicate dropped (canonical one lives
  in `sessions/serializers.py`); dead `MagicLinkRequestDTO` deleted.
- `events.TOPIC_USER_REGISTERED` back-compat alias — use
  `EVENT_USER_REGISTERED`.

### Changed
- Adapted to stapel-core's shim scrub: imports moved to
  `stapel_core.django.jwt.{provider,utils,authentication}`; captcha test
  overrides use the namespaced `STAPEL_CAPTCHA` setting.

## [0.6.0] — 2026-07-17

Owner directive: how each auth method is *displayed* must be configurable on
the backend exactly like its *availability* already is. Contract-expanding
minor (postmortem §60: expansion is never a patch), plus the security-profile
inventory pass (owner directive p.5) and an owner follow-up on OTP metadata.

### Added — per-method placement + icon in the capabilities contract
- `AUTH_<METHOD>_PLACEMENT` settings (email/phone/password/magic_link/sso/oauth/qr/passkey)
  — sibling axis to the existing `AUTH_*_LOGIN` gates, `main | overflow | bottom`.
  Sane defaults: email/phone=`main`, password/magic_link=`overflow`,
  sso/oauth/qr/passkey=`bottom`.
- `GET /auth/api/v1/capabilities/` now emits `methods: AuthMethodInfo[]` —
  one entry per login method with `placement`, a fixed `order`, a derived
  `interaction` (`inline` for `main`; `modal` for everything else, except
  oauth/sso which always `redirect`) and a bundled `icon_svg` (hand-drawn,
  license-clean, 24x24, `currentColor`) a host frontend may override.
- `docs/capabilities.json`: 8 new `auth.placement` axes (25 axes total, up
  from 17).

### Added — OTP metadata (frontend must not guess code length/ttl/cooldown)
- `GET /auth/api/v1/capabilities/` now emits `otp: OtpMeta` —
  `email_code_length`/`phone_code_length` (4), `totp_code_length` (6),
  `ttl_seconds` (600) and `resend_cooldown_seconds` (30), single-sourced
  from the same constants/settings the backend actually validates against
  (`otp/constants.py::OTP_CODE_LENGTH`, `TOTPService.CODE_LENGTH`,
  `AUTH_OTP_TTL`, new `AUTH_OTP_RESEND_COOLDOWN` setting) — a frontend that
  previously hardcoded a 6-box code input against a 4-digit backend now has
  a contract field to read instead.
- `AUTH_OTP_RESEND_COOLDOWN` (default 30s) is a new setting; `AUTH_OTP_TTL`
  (already existed, default 600s) is now actually wired into OTP expiry —
  previously the setting was read nowhere and the expiry was a hardcoded
  `timedelta(minutes=10)` that merely happened to match the default.

### Added — OAuth account links (security-profile inventory)
- `GET/POST /oauth/links/`, `DELETE /oauth/links/{provider}/` — connect/
  disconnect additional OAuth provider accounts on an already-authenticated
  user, distinct from the login/registration OAuth flow. New
  `LinkedOAuthAccount` model; the account a user originally registered/
  logged in with is reported as `primary` and is not removable through this
  endpoint. Unlink is blocked (`error.400.last_auth_method`) when it would
  leave the account with no way to sign in.
- `security/status` (`connected_oauth`) now reports every linked provider,
  not just the primary one.

### Changed — "magic link" renamed to "email link" in user-facing text
- English error/summary strings and the response message updated
  (`error.400.magic_link_invalid`, `error.429.magic_link_rate`, the
  `MagicLinkViewSet` endpoint summaries). Error *keys* are unchanged.

### Security-profile inventory (owner directive p.5)
Sessions (list/revoke-one/revoke-all), TOTP (setup/confirm/disable +
recovery codes) and passkeys (list/register/authenticate/remove) were
already complete. Password change (old+new) was already complete. OAuth
account links (list/link/unlink) were missing entirely — implemented above.

### Changed — dependency ceiling
- `stapel-core>=0.10,<0.11` → `<0.12` (stapel-core released 0.11.x — bus
  singleton lifecycle, config-checks, validation error params/language).
  Suite passes against stapel-core 0.11.2; lower bound stays `>=0.10` since
  nothing here depends on a 0.11-only feature.

## [0.5.9] — 2026-07-16

### Fixed
- Release hygiene: v0.5.8 CI was red because `docs/capabilities.json` was
  regenerated before the version bump (envelope pinned `0.5.7`). Regenerated
  at `0.5.9`; retag per house precedent (0.5.8 never reached PyPI).

## [0.5.8] — 2026-07-16

### Changed
- **v1 canon sweep §60** (api-versioning.md §2, §6): `urls.py` renamed to
  `urls_v1.py` (paths inside unchanged); the new root `urls.py` mounts it
  under `v1/` and re-exports the per-feature factories + `GATE_REGISTRY`.
  Hosts including `stapel_auth.urls` under `auth/api/` now serve
  `/auth/api/v1/...`; bare `/auth/api/...` no longer exists (no live external
  consumers; sweep lands before the §3 API00x gates are enabled).
- Contract artifacts regenerated (`make contract`): `/v1/` in every path and
  `auth_api_v1_*` operationIds — the single expected diff of the sweep.
- Absolute-URL builders follow the canon: SSO SAML/OIDC callbacks, magic-link
  verify, suspicious-login revoke URL, OAuth callback URI, OpenID discovery
  endpoints now emit `/auth/api/v1/...`.
- `_capabilities.py` canonical_prefix → `/auth/api/v1`.
- Lint hygiene to a clean `stapel-verify`: explicit `# noqa: R007/R006` on
  pre-existing findings (documented endpoints not yet attached to flows).

## [0.5.7] - 2026-07-16

### Fixed — user.session_created / user.session_revoked are now actually emitted

The emit schemas (`schemas/emits/user.session_created.json` /
`user.session_revoked.json`) were published without any `emit()` in the
code — a silent contract lie (2026-07-16 audit). Session lifecycle events
now go through the transactional outbox atomically with the `UserSession`
write, mirroring `staff_roles`:

- `SessionService.create` emits `user.session_created` (login, refresh
  legacy-token path, SSO, QR) — `ip_address` omitted when unknown (the
  schema field is a plain string).
- `SessionService.revoke_by_jti` (logout), the new
  `SessionService.revoke_session` (per-device revoke endpoint) and
  `SessionService.revoke_all` (password change, revoke-all endpoint) emit
  `user.session_revoked` — once per session, idempotent re-revokes stay
  silent.
- The suspicious-login "this wasn't me" endpoint now revokes through
  `SessionService.revoke_all` — its raw queryset update previously skipped
  JTI blacklisting *and* would have skipped the event.
- `events.py`: payload dataclasses + registry entries for both events.

Tests validate the outbox payloads against the published JSON schemas.

## [0.5.6] - 2026-07-14

### Fixed — contract drift blocking every publish since 2026-07-09

- `v0.5.5` was tagged but never reached PyPI: `docs/schema.json` was
  generated with drf-spectacular 0.29, which renders a blank-eligible
  URLField/EmailField as a flat typed string; 0.30 (what a fresh install
  actually resolves via the floating `drf-spectacular>=0.27` pin) renders it
  as `oneOf[typed, maxLength:0]` instead. Unrelated to the SSOConfig width
  fix below, but failed `test_contract_has_no_drift` on the canonical Python
  3.12 CI leg and blocked the publish job from ever running. Regenerated
  against drf-spectacular 0.30 to match CI's actual resolution.

## [0.5.5] - 2026-07-14

### Fixed — OAuth/SSO URLField truncation (500s) + missing `consume_gdpr` command in installs

- **OAuth avatar**: a pathologically long provider avatar URL now degrades to
  no-avatar on signup instead of 500ing (`otp/views.py`) — belt-and-suspenders
  with `stapel-core` 0.10.1 widening `users_user.avatar` 200→500.
- **`SSOConfig.saml_sso_url` / `saml_slo_url` / `oidc_discovery_url`** widened
  `URLField` 200→500 (migration `0014_widen_sso_config_urls`, expand-only).
  Same bug class as the OAuth avatar: Django's `URLField` default is
  varchar(200), and real IdP endpoints (Okta/Azure AD SSO URLs with encoded
  query params) routinely exceed it.
- **Packaging**: `stapel_auth.management` / `stapel_auth.management.commands`
  (the `consume_gdpr` bus consumer used in microservices mode) were missing
  from `[tool.setuptools].packages` — every PyPI install was silently missing
  `manage.py consume_gdpr`. Same class of bug as `stapel-core`'s
  `projections` subtree miss (7b0eb1e); found by a packaging audit
  (tree-vs-pyproject diff) done alongside this release.
- **Dependency pin**: `stapel-core` requirement was still `>=0.8,<0.9` — three
  major releases behind every other stapel-* module (`>=0.10,<0.11`) and
  behind the 0.10.1 this release's avatar fix pairs with. A clean install of
  `stapel-auth` would have resolved a `stapel-core` that predates both the
  avatar widening and the `Projection`/config-seam features other code here
  already assumes. Bumped to `>=0.10,<0.11`.

### Added — config axes + `docs/capabilities.json`, the fourth contract artifact (capability-config.md §1-§2/§5, ETALON)

- **`AUTH_ANONYMOUS`** (new setting, default `True`) — anonymous auth is its own
  config axis with its own URL factory `get_anonymous_urls()` (exported from the
  package root). Fixes §5-A1: `/anonymous/` used to live inside the otp factory
  under the email/phone gates, so disabling email+phone silently 404'd guest
  auth while `GET /capabilities/` kept hardcoding `anonymous: true`. The
  capability now reads the setting; the view 403s per-request on always-on
  mounts. Path and URL name unchanged.
- **`AUTH_TOTP`** (new setting, default `True`) — gates the `/totp/*` block of
  `get_mfa_urls()` exactly the way `AUTH_PASSKEY_LOGIN` gates `/passkey/*`
  (§5-A2; TOTP was the only ungated method-functionality). `GET /capabilities/`
  grows an additive `mfa: {totp, passkey}` section.
- **`conf.py` on `stapel_core.conf.AppSettings`** (§5-A3) — the bespoke
  accessor is gone; same public surface (`auth_settings.<KEY>`, `AuthSettings()`,
  `DEFAULTS`, `OAuthProviderConfig` coercion). `no_env` now protects secrets,
  dotted-path seams and every boolean gate (env strings are truthy);
  `INTERNAL_SERVICE_KEY` no longer falls back to the environment.
- **`docs/capabilities.json`** (§5-A4) — machine-readable config-axis manifest,
  emitted by `make contract`, drift-gated by `make contract-check` +
  `tests/test_contract.py` like the triad. Derived: axis key/kind/default/group
  from `DEFAULTS`, `gates.operations` from the new `urls.py: GATE_REGISTRY`
  (every factory declares its flags + patterns via `_gated()` where the gating
  executes) cross-referenced with `schema.json` operationIds. Curated:
  `docs/capabilities.meta.json` (business_label/summary per axis, provides,
  requires, extension_points) — missing/stale meta is a loud emission error.
  17 axes; the schema/flows/errors triad stays byte-identical with all
  defaults on.

### Added — per-module contract emission: `schema` + `flows` triad (contract-pipeline.md Wave 1, ETALON)

stapel-auth now emits its **own** API contract per-module, completing the triad
`docs/{schema,flows,errors}.json` (`errors.json` already existed). The frontend
codegen can now read auth's committed artifacts instead of the monolith aggregate
at floating `main` — contract-pipeline.md verdict **A** (contract = a reviewable,
version-pinned commit). This is the reference implementation the other four
pair-backends copy.

- **Harness** (reuses `stapel_tools.codegen`, adds ~90 lines of per-module config):
  - `_codegen_settings.py` — single source of truth for the `settings.configure`
    block, shared with `conftest.py` (extracted, no test-behavior change); a
    `contract=True` mode swaps in the production `REST_FRAMEWORK`.
  - `codegen_urls.py` — mounts `stapel_auth.urls` + `stapel_gdpr.urls` at the
    canonical `auth/api/` prefix (exactly as the monolith does), so emitted paths
    are `/auth/api/...` not bare `/password/login/`.
  - `_codegen.py` — the `python -m stapel_auth._codegen --out docs` entrypoint.
- **`docs/schema.json`** (new) — drf-spectacular OpenAPI for auth only, canonical
  prefix; **`docs/flows.json`** (new location) — `generate_flow_docs` machine
  artifact with canonical-prefix endpoint paths.
- **Byte-identity** with the monolith aggregate's auth slice (paths under
  `/auth/api/` + their component closure) is **exact**: 90 paths, 112-component
  closure, zero diff vs both the committed and freshly-regenerated monolith.
  `flows.json` and `errors.json` are byte-identical too.
- **Gate:** `make contract` / `make contract-check`; `tests/test_contract.py`
  (drift + determinism + canonical-prefix + monolith-slice identity) is the
  CI-enforced gate.
- Two emission subtleties documented in MODULE.md (they are why auth is the
  etalon): `SCHEMA_PATH_PREFIX` must be pinned to `"/"` to reproduce the
  multi-module common prefix in operationIds, and drf-spectacular emits on its
  *default* settings here (its singleton snapshots settings at import time), so
  the harness must reproduce the defaults — not apply `get_spectacular_settings`.

## [0.5.4] - 2026-07-08

### Added — admin-suite AS-5: `@access` category rollout + `StapelModelAdmin`

Applies the `stapel_core.access` category decorators (admin-suite §0/AS-5
sweep) to this module's models and switches their `ModelAdmin`s to
`StapelModelAdmin` so the category cosmetics (read-only rendering, secret
masking) take effect.

- `@access.ops` (read-only journal): `PhoneVerification`, `EmailVerification`,
  `LoginAttempt`, `AuthAuditLog`, `AuthenticatorChangeRequest` (the latter's
  `change_token` additionally pinned via `secret_fields` — a live bearer
  token, not just workflow metadata).
- `@access.secret` (superuser-only, masked fields): `ServiceAPIKey`,
  `RefreshTokenTracker`, `TOTPDevice` (`secret_fields=('secret',
  'backup_codes')`), `SSOConfig` (`oidc_client_secret`).
- New admin registrations for previously-unregistered ops/secret models:
  `AuthAuditLogAdmin`, `TOTPDeviceAdmin`, `SSOConfigAdmin`.
- Fixed a latent masking bypass while migrating: `ServiceAPIKeyAdmin` and
  `AuthenticatorChangeRequestAdmin` each listed their now-secret field
  (`key`, `change_token`) directly in `readonly_fields`, which renders the
  raw value in a second, unmasked field alongside the mixin's masked
  placeholder — removed those entries so masking is the only rendering.
- Left `business` (undecorated) after review: `UserSession`,
  `PasskeyCredential`, `Organization`, `OrgMembership`,
  `VerificationPreference` — see MODULE.md for the reasoning.
- No migration: the decorator is a plain class attribute (verified via a
  `makemigrations --check --dry-run` harness against a real settings shape).

### Added — ru error catalog + bilingual error reference (i18n-shipping волна 1)

Reference application of the `stapel_core.i18n` catalog contour to the `errors`
domain (i18n-shipping.md §5) — the pattern wave-2 sweeps copy 1:1.

- `translations/errors.ru.json` — flat `{code: text}` ru catalog covering all
  116 auth error keys, with `translations/.state.json` provenance sidecar.
  Provenance is honest: **112** keys seeded from the curated `stapel-translate`
  builtin fixtures (`origin: seed:stapel-builtin` — no tokens spent), **4**
  auth-only keys machine-translated (`origin: llm`, unreviewed — the gate's
  W-counter). `translations/.errors.ru.llm-cache.json` is the committed,
  content-hash translation cache.
- `docs/errors.en.md` · `docs/errors.ru.md` — generated human-readable
  references (`generate_error_docs`); README + MODULE.md link both languages
  (lint R100 clean). MODULE.md documents the i18n seam semantics (registry
  `update`/last-wins override shim, catalogs merge/later-wins, params preserved).
- `tests/test_error_i18n.py` — `check_translation_catalogs` gate (E on
  missing/stale/params-mismatch/byte-instability all green) + env-gated regen
  (`STAPEL_REGEN_ERROR_I18N=1 pytest tests/test_error_i18n.py::test_regen`).

### Added — `avatar_url` on `user.registered` (feat-oauth-avatar, auth half)

Wires the OAuth avatar through to the event so downstream consumers (e.g.
profiles → CDN re-fetch, per the recon verdict) have something to subscribe
to; auth itself never fetches or stores the image, it only forwards the URL
the provider handed back.

- `UserRegisteredPayload.avatar_url: str | None = None` (`events.py`).
- `schemas/emits/user.registered.json` gains `"avatar_url": {"type":
  ["string", "null"]}` — required by the schema's `additionalProperties:
  false`, so this was a hard prerequisite for emitting the field at all.
- `_notify_user_registered` (`otp/views.py`) now sends `user.avatar or None`
  as `avatar_url`. Only the OAuth registration path
  (`_resolve_oauth_user`) ever populates `User.avatar`; every other
  `auth_type` emits `avatar_url: null`.

### Added — staff role assignments + `staff_roles` JWT claim (admin-suite AS-2)

Producer half of the staff-role transport: role *definitions* stay in deploy
config (`stapel_core.access`, AS-1); role *assignments* now live in the auth
service — the single writer (invariant A2) — and ride every staff JWT.

- **`StaffRoleAssignment` model** (migration `0013`, table
  `staff_role_assignments`): user → role-name string, unique per pair,
  `assigned_by` audit column. `role_name` is validated against the
  `STAPEL_ACCESS["ROLES"]` registry at write time — deliberately not a FK
  into a DB catalog, so definitions stay un-editable at runtime (MAC).
  Declared `@access(view/add/change/delete = "high")` — clearance-HIGH
  surface under the AS-1 mandate. Targets must already be staff
  (dormant-privilege guard: `error.400.staff_role_target_not_staff`).
- **Services** `assign_staff_role` / `revoke_staff_role` / `staff_roles_for`
  (`staff_roles.py`; exported from the package root): idempotent writes that
  emit `staff.role.assigned` / `staff.role.revoked` (schemas in
  `schemas/emits/`, payload carries the full role list *after* the change)
  through the transactional outbox — row and audit event commit together.
- **`staff_roles` JWT claim.** Every token-issuance path (obtain pair,
  refresh, password reset, QR confirm, SSO, `TokenService`,
  `_issue_session_tokens`) now goes through
  `staff_roles.create_tokens_for_user`, which appends the sorted role list to
  staff/superuser payloads. **Staff tokens always carry the claim — an empty
  list included** (authoritative-empty: this is what makes a revocation reach
  consumer services under REPLACE sync-down). Non-staff tokens carry no claim
  (identical to pre-AS-2 tokens: consumers must treat absence as "no
  information"). Refresh re-reads roles from the DB, so revocation latency is
  bounded by the access-token lifetime (A3); immediate revocation remains the
  Redis user-blacklist.
- **Django admin** for assignments (immutable rows — change = revoke +
  assign; writes routed through the services so audit events are never
  skipped) and a management **API**: `GET|POST /staff-roles/`,
  `DELETE /staff-roles/<assignment_id>/` — gated by staff +
  `authentication.*_staffroleassignment` model permissions
  (mandate / DAC / superuser; never "any staff").
- **AS-1 wiring for the auth service**: `stapel_auth.staff_roles.assignment_roles`
  is a ready-made `STAPEL_ACCESS["ROLE_SOURCES"]` source reading the
  assignment table directly (fresher than any claim). See MODULE.md.
- New error keys: `error.400.unknown_staff_role`,
  `error.400.staff_role_target_not_staff` (docs/errors.json regenerated).

**Heads-up (в.3, breaking on the consumer side when the stapel-core
counterpart lands):** the sync-down in stapel-core's
`get_or_create_user_from_jwt` switches from "upgrade-only" to **REPLACE from
the claim** for `staff_roles` AND for the `is_staff` / `is_superuser`
booleans — auth becomes the source of truth for staff status everywhere.
Migration path for services that today rely on *locally assigned* staff
flags on shadow users: recreate those staffs in the auth service (e.g. via
`POST /admin-users/` + role assignment) **before** upgrading stapel-core;
after the upgrade a login with a fresh token overwrites local
`is_staff`/`is_superuser` with the auth-side values. Old tokens without the
claim change nothing (absence = no information), so mixed fleets degrade
safely during rollout.

### Fixed — shadowed `admin.py` never loaded in production (auth-tails)

- **The Django admin registrations were invisible in production.** The
  `ModelAdmin` classes for `PhoneVerification`, `EmailVerification`,
  `ServiceAPIKey`, `RefreshTokenTracker`, `AuthenticatorChangeRequest` and
  `LoginAttempt` lived in a top-level `admin.py`, but the sibling `admin/`
  package (`admin/__init__.py`) shadows it at the same import path
  (`package-dir = {"stapel_auth": "."}`). Django's admin autodiscover imports
  `stapel_auth.admin`, which resolved to the empty package, so **none of these
  models appeared in the Django admin site.** The registrations now live in
  `admin/__init__.py` and load normally; `admin.py` is deleted. This is a
  behavioural change — the six models now show up in the admin as originally
  intended. No `AlreadyRegistered` conflict: the `admin/` package contained
  only DRF views/serializers/DTOs, no competing `ModelAdmin`.

### Fixed — root-relative URLs break under a mount prefix (auth-tails)

- **QR `scan_url` no longer hardcodes the `/auth/api/` mount point.**
  `QRAuthViewSet.generate` built the scan URL from a literal
  `f"/auth/api/qr/{key}/scan/"`, which is wrong whenever the auth URLconf is
  `include()`d under a different prefix (see `stapel_core.django.mounts` /
  `STAPEL_MOUNTS`). It now derives the path with
  `reverse("qr_scan", kwargs={"key": key})`, so the returned URL follows
  whatever prefix the app is mounted under.
- **OAuth step-up TOTP redirect is anchored to `FRONTEND_URL`.** The OAuth
  callback redirected the browser to a bare `/totp-challenge?…` (a *frontend*
  route) on the backend origin. It now prefixes `FRONTEND_URL`, matching the
  SSO / magic-link redirect convention, so the browser lands on the SPA. When
  `FRONTEND_URL` is unset the redirect stays same-origin-relative, preserving
  the previous behaviour.

### Fixed — five latent crashes exposed by the new coverage suite (quality-auth-coverage)

All five were invisible to the old suite because the affected paths were either
mocked end-to-end or never exercised; the new tests run the real
implementations and every fix ships with regression tests.

- **`cleanup_expired_anonymous_users` raised `AttributeError` on every call.**
  It read `settings.ANONYMOUS_USER_LIFETIME` — a key that does not exist (the
  configured key is `STAPEL_AUTH['ANONYMOUS_USER_LIFETIME_DAYS']`, an int number
  of days, not a `timedelta`), so any invocation crashed before deleting
  anything. Now reads `auth_settings.ANONYMOUS_USER_LIFETIME_DAYS` and builds the
  cutoff with `timedelta(days=...)`.
- **`MagicLinkService.send` raised `NameError` on every real call.** The method
  logs `AuditService.log('magic_link_sent', ...)` but the module never imported
  `AuditService`, so a real magic-link send crashed right after enqueuing the
  email. The import now lives at module scope.
- **Session revoke/confirm endpoints returned HTTP 500 on success.**
  `SessionViewSet.revoke_one`, `confirm_session` and `revoke_all` did
  `from .dto import SimpleStatusResponse`, but the class lives in the top-level
  `stapel_auth.dto` — the success path raised `ImportError` *after* the DB
  mutation (session already revoked/confirmed, then 500 to the client). Imports
  fixed; the endpoints now return their documented 200 payloads.
- **Logout never revoked the session row.** `_logout` imported `SessionService`
  from `otp.services` (it lives in `sessions.services`) inside a swallowed
  `except`, so `revoke_by_jti` never ran and a logged-out session stayed in the
  user's active-sessions list until token expiry. Import fixed.
- **SSO login crashed on `UNIQUE(user_sessions.jti)`.**
  `SSOUserService.issue_session_and_redirect` called `_issue_session_tokens`
  (which already registers the refresh jti as a `UserSession`) and then created
  a *second* session from the same jti — every real SSO login died on the unique
  constraint. It now mints the token pair directly and persists the session
  once, keeping the SSO-specific `sso_login` audit event.

### Changed — coverage raised from 81% to ≥99% line (quality-auth-coverage)

- ~450 tests added across 12 new test files: real `MagicLinkService`,
  `PasskeyService` against a mocked `webauthn.*` crypto boundary, real `pyotp`
  TOTP flows, SessionViewSet/SecurityStatus/AdminAuditLog endpoints, SSO
  service/views branch matrix, `consume_gdpr` via `call_command` + MemoryBus,
  admin registrations via the registry pattern, URL factory gates, OAuth
  provider branches, JWKS RS256, token introspection, and fault-injected
  defensive branches. One `# pragma: no cover` in the whole codebase
  (`admin/serializers.py` — E.164 length guard unreachable after
  `is_valid_number`).

### Removed — dead code excised (quality-auth-coverage)

- **`security_views.py` deleted (271 statements).** The module was fully
  superseded by the feature packages (`security/`, `magic_link/`, `mfa/`) and was
  no longer wired into `urls.py` nor imported anywhere. Not part of the public
  surface (`__init__.py` lazy exports, `MODULE.md`, `README`, `schemas/`), so its
  removal touches no documented API.
- **`oauth/providers.py` deleted (148 statements).** A byte-for-byte duplicate of
  the canonical top-level `oauth_providers.py` (which `apps.py` registers and
  `__init__.py` re-exports `PROVIDER_REGISTRY` from). Its only live reference —
  `oauth/services.py` importing `get_enabled_providers` — now points at the
  canonical module; the function is behaviour-identical (both query the shared
  `stapel_core.oauth` registry).
- **`OTPViewSet.set_auth_cookies` removed** — an unreferenced helper with zero
  call sites (JWT-cookie setting goes through `stapel_core.django.utils`
  directly).
- **Unused `PasswordResetSerializer` / `PasswordResetConfirmSerializer` removed**
  from `password/serializers.py` — never imported; the live password-reset flow
  uses the `PasswordReset{Email,Phone}{Request,Verify}Serializer` family.
- **`magic_link/dto.py` deleted** — `MagicLinkRequestDTO` was never imported
  anywhere (the magic-link views respond through their serializers directly).
- These modules/symbols were dead (not reachable from any URL, registry, or
  public export), so despite being source-level removals the change is
  behaviour-preserving — released as a patch.

### Deprecated — step-up unification: the verification envelope is the one step-up contract (auth-stepup-unification)

- **`POST /totp/step-up/` is deprecated (removed in 1.0).** The endpoint keeps
  working through 0.x but now advertises its retirement: the response carries a
  `Deprecation: true` header and a `Link: …; rel="successor-version"` pointing at
  the `/verification/` flow, the OpenAPI operation is flagged `deprecated`, and
  the endpoint logs a single deprecation warning per process. The one step-up
  contract of Stapel is the verification envelope (`@requires_verification` +
  `error.403.verification_required`); the hand-rolled `X-Step-Up-Token` mechanism
  is superseded.
- **Server-side grant bridge for zero-downtime brownfield transit.** A
  successful `/totp/step-up/` now *additionally* writes a
  `stapel_core.verification` grant for every scope in the new
  `STAPEL_AUTH['LEGACY_STEP_UP_GRANT_SCOPES']` setting (default `["sensitive"]`,
  `max_age = STEP_UP_TTL = 900`). An already-deployed legacy frontend that still
  calls `/totp/step-up/` therefore keeps passing endpoints migrated to
  `@requires_verification`, so a host can migrate its backend guards first and
  its frontend later. Set `LEGACY_STEP_UP_GRANT_SCOPES = []` to disable the
  bridge and issue only the legacy token.
  - **Semantics differ, deliberately:** the legacy `X-Step-Up-Token` is
    one-time; the bridged grant is *reusable within `max_age`* per scope. For
    strict one-shot behaviour, keep `max_age` short. The bridge grants only the
    configured scopes — a step-up never satisfies an unrelated scope (no scope
    escalation).
- **`TOTPService.create_step_up` / `consume_step_up` emit `DeprecationWarning`.**
  Both keep working; the deprecated endpoint uses an internal, warning-free
  helper so a legit call does not double-warn. Removed in 1.0.
- **`error.403.step_up_required` marked deprecated** (kept in the catalogue for
  hosts that still raise it; no stapel-auth code raises it). Removed in 1.0. No
  new error key is introduced and `errors.json` is unchanged.
- **`totp_step_up` audit event is now emitted** by the legacy endpoint on
  success (the `AuditLog` choice already existed but was never written).
- **`@stapel/auth-react`: no change** — the package is envelope-only; no
  `X-Step-Up-Token` bridge is added on the client, per design.

### Added — declarative error remediation + committed `errors.json` (error-remediation)

- **Error registry moved onto the core declarative mechanism with
  `remediation`.** `errors.py` now calls
  `register_service_errors(AUTH_ERRORS, remediation=AUTH_REMEDIATION)`, declaring
  a machine-readable recovery hint (`retry`, `wait_and_retry`, `reauthenticate`,
  `verify`, `fix_input`, `contact_support`, `bug`) for every auth key across the
  verification / login / QR / OAuth / password / magic-link / passkey / SSO /
  captcha flows. The backend en text and remediation are now the canon the
  frontend derives from (previously the frontend guessed remediation from a
  heuristic and shipped its own en fallbacks). Several keys carry deliberate
  intent the heuristic got wrong — OAuth/captcha/passkey ceremonies are
  `retry`-able (not `fix_input`); a disabled account or unconfigured SSO needs
  `contact_support`; `send_failed` is transient (`retry`).

- **`docs/errors.json` committed as a codegen artifact with a drift gate.**
  Generated by core's `generate_error_keys` (the array of `{code, status,
  params, remediation, en}` the frontend consumes), covering every key the
  service can raise — auth's own plus the cross-cutting `verification` and
  `captcha` keys. `tests/test_error_keys.py` is the drift gate: it regenerates
  and asserts byte-for-byte equality with the committed artifact (regenerate
  with `STAPEL_REGEN_ERROR_KEYS=1 pytest tests/test_error_keys.py`), exactly like
  the flow-doc gate.

## 0.5.3 — 2026-07-06

### Changed
- Pinned `stapel-core` to the `>=0.8,<0.9` window (library-standard §7.1: one
  minor window; floor `0.8.0` is published on PyPI — no pin into the void).
- CI: added the release-track job (library-standard §7.4) — installs the package
  the way an end user does (`pip install .`, dependencies resolved from PyPI
  strictly by the declared pins, no git-main core, no editable siblings), asserts
  `stapel-core` resolves inside the `0.8` window, and runs an import smoke.
  Advisory (continue-on-error) until the whole stapel graph is on PyPI; becomes
  the blocking precondition for a `vX.Y.Z` tag once it is.


## 0.5.2 — 2026-07-06

### Packaging
- Tests excluded from the built wheel/sdist (the `stapel_auth.tests`
  subpackage is no longer listed in `[tool.setuptools] packages`). Added
  `[project.urls]`, completed the trove classifiers (MIT/OSI, Python 3.13,
  `Typing :: Typed`, OS Independent, `3 :: Only`, Development Status) and a
  `[tool.ruff]` lint section (single source shared with the git hooks/CI).


## 0.5.1 — 2026-07-05

### Fixed — complete OpenAPI (`@extend_schema`) coverage for the last untyped views

drf-spectacular reported five auth endpoints as "unable to guess serializer"
(APIViews / plain ViewSets whose request bodies it could not introspect),
producing a thin, untyped generated client. Each now carries an
`@extend_schema` reflecting its real contract (request serializer / `request=None`
for bodyless POSTs, response serializers, real error status codes):

- `TokenIntrospectView` (openid) — added `TokenIntrospectRequestSerializer` +
  `TokenIntrospectResponseSerializer` (RFC 7662 shape: always `active`, plus the
  claim fields when valid); `401` for missing/invalid service API key.
- `PasskeyViewSet.register_begin` (mfa) — `request=None`, 200 options / 400.
- `QRAuthViewSet.confirm` / `reject` (qr) — `request=None`, 200 `SimpleStatus`.
- `SessionViewSet.confirm_session` (sessions) — `request=None`.
- `SAMLACSView` (sso) — external IdP form POST documented as `OpenApiTypes.OBJECT`
  (base64 `SAMLResponse`, SAML 2.0 spec-defined), 302 redirect.

Also fixed a misplaced `@extend_schema_view` that listed `AuthViewSet` method
names on `SessionViewSet` (12 "argument not found on view" warnings): the tag
decorator moved to `AuthViewSet` (its real home), and `SessionViewSet` got its
own correct `["Session"]` tags. No runtime/contract change — annotations only.

Known residual: the `LoginResponse` polymorphic union still emits two
"discriminator field status" warnings — `AuthResponse.status` is a 5-value enum,
so it cannot serve as a fixed OpenAPI discriminator key. Both sub-serializers are
fully typed; resolving this cleanly is a schema-modeling change out of scope here.

## 0.5.0 — 2026-07-05

### Added — bilingual flow SA-document trees + release-gate drift check (flow-system.md §4)

stapel-auth is the reference module for the rendered flow SA-documents. The
committed `docs/flows/{en,ru}/` trees (mermaid step diagram, numbered steps,
endpoint table with the step-up verification contract) are generated from the
single language-agnostic `docs/flows/flows.json` by `generate_project_docs`
(stapel-core 0.5.0). The README tags both trees:
`[Flows (EN)](docs/flows/en/README.md) · [Флоу (RU)](docs/flows/ru/README.md)`.

- `tests/test_flow_docs.py` is the **release-gate drift check** (attributes-
  static discipline): it regenerates into a temp dir and asserts byte-for-byte
  equality with the committed tree. Regenerate after a flow/catalog change with
  `STAPEL_REGEN_FLOW_DOCS=1 pytest tests/test_flow_docs.py` and commit
  `docs/flows/`.
- Requires **stapel-core >= 0.5.0** (the `FLOW_DOC_RENDERER` seam,
  `generate_project_docs`, `DOC_LANGUAGES`).

No code or contract change to the auth service itself — flows/catalogs are
unchanged; this ships the rendered documentation artifacts and their gate.

## 0.4.1 — 2026-07-05

### Fixed — `user.registered` emit is now truly best-effort under ATOMIC_REQUESTS

- `otp.views._notify_user_registered` now emits inside its own
  `transaction.atomic()` block. Previously the "swallow never fails
  registration" claim held only in autocommit mode: under `ATOMIC_REQUESTS=True`
  the helper ran inside the request transaction, and a failing emit (outbox
  insert / schema validation) marked that transaction rollback-only
  (`comm/actions.py`). Swallowing the exception did not help — the next DB query
  (`_issue_session_tokens`) raised `TransactionManagementError`, 500-ing the
  request and rolling back the just-created user. Wrapping emit in a nested
  atomic isolates the failure to a savepoint (Django rolls it back and clears
  `needs_rollback`), so registration survives an emit failure in **both** modes.
  Being inside an atomic also silences the emit-outside-atomic guard's
  per-registration WARNING spam in autocommit mode. Transactional-outbox
  ordering is preserved. New regression tests cover both request modes.

## 0.4.0 — 2026-07-05

### Changed — flow i18n reference migration (flow-system.md §2, stapel-core 0.4)

- The three business flows (`auth.passwordless_login`, `auth.password_login`,
  `auth.step_up_verification`) migrated to i18n keys: the `flows.py` literals
  are now the canonical **English** source texts (previously Russian) with
  implicit keys `flow.<id>.title` / `flow.<id>.description` /
  `flow.<id>.step.<order>.note`. This changes the `title`/`description`/`note`
  literals in generated flows.json/markdown to English — hence the minor bump;
  flow ids, structure, orders and API bindings are unchanged.
- New committed catalogs `translations/flows.en.json` and
  `translations/flows.ru.json` (full 20-key set; en mirrors the literals).
  `stapel_core.flows.i18n.resolve_flow_texts` / `generate_flow_docs --lang ru`
  renders the Russian texts from them; other languages fall back to English or
  go through the DOC_TRANSLATOR seam on demand.
- Drift gates in `tests/test_flow_i18n.py`: en catalog == in-code literals,
  ru catalog covers exactly the same key set, resolution renders Russian.
  This is the first-instance pattern every module copies.
- Requires `stapel-core>=0.4.0,<0.5`.

## 0.3.4 — 2026-07-05

### Changed
- CI/pre-commit/pre-push now run `stapel_core.lint.emit_check` (outbox-atomicity
  gate, stapel-core 0.3.3+). Hooks guard-fall back to a skip when core is older.
- `otp.views._notify_user_registered`: annotated the `user.registered` emit with
  an `emit-check: ok` pragma (EMIT002). It is a best-effort post-commit
  notification fan-out — the helper holds no ORM write of its own, the caller
  creates+commits the user independently, and the swallow is intentional so a
  broker/listener outage never fails registration. No behaviour change.

## 0.3.3 — 2026-07-05

### Fixed
- Migration drift under Django 6: the committed migrations were behind the
  models. `0012` regenerates the missing `AlterField`s —
  `AuthAuditLog.event_type` choices (new audit event types added to the enum
  without a migration) and the `SSOConfig.id` / `OrgMembership.id` primary keys
  (created as `AutoField` in `0010` but the app config declares
  `BigAutoField`). `makemigrations --check` is now clean.

## 0.3.2 — 2026-07-04

### Added
- `MODULE.md` — agent-facing extension-point map (part of the July 2026
  framework-wide documentation sweep). No functional changes.

## 0.3.1 — 2026-07-03

### Added
- Verification flows wired to `stapel_core.verification`: registers
  otp_email/otp_sms/totp/passkey factors, challenge endpoints under the
  auth prefix, per-user verification-method preference (migration 0011),
  verification Function with committed schema.


## 0.3.0 — 2026-07-02

### Added
- Step-up verification factors (`otp_email`, `otp_phone`, `totp`,
  `passkey` — interchangeable) registered with
  `stapel_core.verification`; three verification endpoints
  (initiate / verify / status) drive any `@requires_verification`
  challenge in any service.
- Exemplar flows: `auth.passwordless_login`, `auth.password_login`,
  `auth.step_up_verification`.

### Changed
- OAuth login no longer forces OTP (`OAUTH_STEP_UP` defaults to False);
  password-login TOTP step-up stays on (`PASSWORD_LOGIN_STEP_UP=True`).
- Canonical event name `user.registered` (comm action name); legacy Kafka
  topic `stapel.auth.user-registered` retired, `TOPIC_USER_REGISTERED`
  kept as an import alias.

## 0.2.0 — 2026-07-02

### Security

- **SAML (sso_service.py)**
  - `SAMLService.parse_response` now enforces `AudienceRestriction`: when the
    assertion carries audiences, one of them must equal our SP entityID for
    the org, otherwise the response is rejected.
  - `InResponseTo` is validated against the AuthnRequest id stored in cache
    at login (`saml_req:{slug}:{request_id}`) and **consumed** — each request
    id answers exactly one response, exactly once. Responses without
    `InResponseTo` are treated as IdP-initiated and still allowed.
  - Assertion **replay protection**: accepted assertion IDs are cached until
    the assertion's `NotOnOrAfter`; presenting the same assertion again is
    rejected.
  - The ACS view passes the org slug into `parse_response`; SAML timestamps
    with fractional seconds are now parsed.
- **OTP / TOTP throttling**
  - Email and phone OTP verify endpoints (`/email/verify/`, `/phone/verify/`)
    now use the same progressive `LockoutService` pattern as password login:
    5 failed codes lock the identifier (15 min, then 1 h, then 24 h),
    returning `423 error.423.account_locked`; success clears the counter.
  - `/totp/challenge/verify/` is throttled per challenge token with the same
    pattern, and `TOTPService.resolve_challenge` now **invalidates the
    challenge after 5 failed codes** — a stolen challenge token yields at
    most five guesses.
- **QR auth device binding**
  - `POST /qr/generate/` sets a random nonce as an httponly cookie
    (`stapel_qr_{key}`) and stores it with the QR record in Redis.
  - `GET /qr/{key}/status/` for `login_request` keys requires the matching
    cookie — a device that merely saw the QR image can no longer poll the
    key and steal the issued session tokens (`403
    error.403.qr_device_mismatch` otherwise).
  - `session_share` scans by an **unauthenticated** scanner are rejected with
    `403 error.403.qr_unauth_scan` unless the QR was generated with the new
    explicit `allow_unauthenticated_scanner: true` flag (default: false).

### Decoupling / stapel-core integration

- **auth → gdpr import broken**: `stapel_auth/gdpr.py` no longer imports
  `stapel_gdpr.models.ReRegistrationHash` directly. The model is resolved
  lazily via the new `REREGISTRATION_MODEL` auth setting (default
  `"stapel_gdpr.models.ReRegistrationHash"`) using
  `django.utils.module_loading.import_string`; if unavailable, deletion
  degrades to a warning instead of failing. stapel-gdpr is not a hard
  dependency.
- **Signals + comm**: user registration completion (email OTP registration,
  OAuth first login, password registration) now
  - sends `stapel_core.signals.user_registered` (kwargs: `user`, `request`),
  - emits `stapel_core.comm.emit("user.registered", {...})` with the same
    payload the legacy `stapel_core.bus.publish` carried
    (`user_id` (uuid string), `auth_type`, `email`), replacing the direct
    bus publish.
- **Event schemas**: `schemas/emits/user.registered.json` added;
  `user.session_created.json` / `user.session_revoked.json` fixed so
  `user_id` is a string (uuid) matching the real payloads.
- **User references**: `models.py` uses `settings.AUTH_USER_MODEL` string
  references in all FKs (migrations unchanged — verified with
  `makemigrations --check`); code paths (`tasks.py`, `security_views.py`,
  `security/views.py`, `mfa/views.py`) use
  `django.contrib.auth.get_user_model()` instead of importing
  `stapel_core.django.users.models.User`.
- **conf.py hygiene**: `otp/services.py` and `password/services.py` read
  `USE_MOCK_SMS_OTP`, `USE_MOCK_EMAIL_OTP` and `MOCK_OTP_CODE` through
  `auth_settings`, so `STAPEL_AUTH={'USE_MOCK_SMS_OTP': True}` works (flat
  Django settings and env vars still work as fallbacks).

### Composable URLs

- `urls.py` split into per-feature urlpatterns factories, exported from
  `stapel_auth.urls`: `get_otp_urls()`, `get_password_urls()`,
  `get_oauth_urls()`, `get_sso_urls()`, `get_mfa_urls()`, `get_qr_urls()`,
  `get_magic_link_urls()`, `get_sessions_urls()`, `get_admin_api_urls()`
  (plus `get_security_urls()` and `get_openid_urls()`).
- Each factory is gated by the corresponding `AUTH_*` feature flags from
  `conf.py` (`enabled=None` consults the flags; `enabled=True/False`
  overrides). `include('stapel_auth.urls')` behavior is **identical** to the
  previous monolithic urls.py — same paths, same names (this module
  assembles all factories with `enabled=True`; per-request flag gating
  remains in the views).

### Cleanup / packaging

- Deleted dead byte-duplicates: the `sso/` package (`sso/service.py`,
  `sso/views.py` — `urls.py` wires the top-level `sso_views.py` /
  `sso_service.py` pair, which stays) and the top-level `tests_extra.py`,
  `tests_services.py`, `tests_sso.py` (the `tests/` package versions are
  canonical). `pyproject.toml` packages list updated.
- Added `py.typed` marker and included it in package-data.
- New tests: SAML audience/InResponseTo/replay, OTP + TOTP lockout, QR
  device binding and unauthenticated-scanner opt-in, URL factory
  equivalence and flag gating, GDPR lazy model resolution, mock-OTP settings
  routing, user.registered signal/emit + schema validation.
