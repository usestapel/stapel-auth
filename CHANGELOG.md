# Changelog

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
