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

Public package API (`stapel_auth/__init__.py`, lazy `__all__`): `auth_settings`, `PROVIDER_REGISTRY`, and the per-feature URL factories `get_admin_api_urls`, `get_magic_link_urls`, `get_mfa_urls`, `get_oauth_urls`, `get_openid_urls`, `get_otp_urls`, `get_password_urls`, `get_qr_urls`, `get_security_urls`, `get_sessions_urls`, `get_sso_urls`, `get_verification_urls`.

## Extension points (fork-free)

### Settings (`conf.py` — `STAPEL_AUTH = {...}` dict)

Resolution order per key: `STAPEL_AUTH['KEY']` → flat Django setting of the same name → env var (for keys in `_ENV_FALLBACKS`) → built-in default. All keys below exist in `conf.py: DEFAULTS`.

| Key | Default | What it customizes |
|---|---|---|
| `FRONTEND_URL` | `None` (env `FRONTEND_URL`) | Redirect base for SSO / magic link / QR login; OAuth `redirect_after` validation |
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
| `JWT_COOKIE_DOMAIN` | `None` (env) | JWT cookie domain override |
| `TOTP_ISSUER` | `'Stapel'` (env) | Issuer shown in authenticator apps |
| `WEBAUTHN_RP_ID` | `None` (env; falls back to request host) | Passkey relying-party ID |
| `WEBAUTHN_RP_NAME` | `'Stapel'` | Passkey relying-party display name |
| `WEBAUTHN_ORIGIN` | `None` (env; falls back to `FRONTEND_URL`) | Expected WebAuthn origin |
| `SSO_ENFORCED_REDIRECT_PATH` | `'/login'` | Redirect path when SSO is enforced for a domain |
| `LOGIN_NOTIFICATION_ENABLED` | `False` | New-device / suspicious-IP login alert emails |
| `REREGISTRATION_MODEL` | `'stapel_gdpr.models.ReRegistrationHash'` | **Dotted path**, resolved lazily in `gdpr.py` — stapel-gdpr is not a hard dependency; point at your own model |
| `INTERNAL_SERVICE_KEY` | `None` (env) | Service-to-service auth key |
| `OAUTH_PROVIDERS` | `{}` | Per-provider credentials: `{'google': {'client_id': ..., 'client_secret': ...}}` (parsed into `OAuthProviderConfig`) |
| `OAUTH_PROVIDER_CLASSES` | 9 built-ins (see below) | **Dotted-path list** of `OAuthProvider` subclasses registered at startup — append your own class to add a provider without touching this repo |
| `AUTH_PHONE_REGISTRATION` / `AUTH_EMAIL_REGISTRATION` / `AUTH_OAUTH_REGISTRATION` / `AUTH_SSO_REGISTRATION` | `True` | Registration method gates |
| `AUTH_PASSWORD_REGISTRATION` | `False` | Password registration gate |
| `AUTH_PHONE_LOGIN` / `AUTH_EMAIL_LOGIN` / `AUTH_OAUTH_LOGIN` / `AUTH_SSO_LOGIN` / `AUTH_QR_LOGIN` / `AUTH_PASSKEY_LOGIN` / `AUTH_MAGIC_LINK_LOGIN` | `True` | Login method gates |
| `AUTH_PASSWORD_LOGIN` | `False` | Password login gate |
| `OAUTH_STEP_UP` | `False` | TOTP challenge after OAuth login |
| `PASSWORD_LOGIN_STEP_UP` | `True` | TOTP challenge after password login |

The `AUTH_*` gates also drive the URL factories in `urls.py`: `include('stapel_auth.urls')` mounts everything (per-request 403 gating), or compose your own URLconf from `get_*_urls()` factories so disabled features 404.

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

### Events & functions (comm surface)

Emitted events (`stapel_core.comm.emit`, transactional outbox; schemas in `schemas/emits/`):

| Event | Payload | When |
|---|---|---|
| `user.registered` | `{user_id, auth_type, email}` (`events.py: UserRegisteredPayload`) | First successful auth of a new account (`otp/views.py: _notify_user_registered`) — profile/workspace creation is done by subscribers |
| `user.session_created` | `{user_id, session_id, device_type, ip_address, created_at}` | Schema declared; **no `emit()` call in code yet** (see gaps) |
| `user.session_revoked` | schema in `schemas/emits/` | Schema declared; **no `emit()` call in code yet** (see gaps) |
| `notification.requested` | via `stapel_core.notifications.request_notification` | All outbound mail/SMS: types `otp_code`, `magic_link_login`, `new_device_login`, `suspicious_login`, `all_sessions_revoked`, `welcome`, `auth_change_requested` / `_reminder` / `_urgent` / `_completed`. Templates live in the notifications service — copy changes are **not** an auth fork |

Provided functions (`functions.py`, registered in `ready()`; schema in `schemas/functions/`):

| Function | Payload → Result | Consumer |
|---|---|---|
| `auth.verification.policy` | `{user_id}` → `{disabled_scopes, enabled_scopes}` | `stapel_core.verification.policy.get_user_policy` (cached core-side) |

Consumed events: `gdpr.export.requested`, `gdpr.delete.requested` — only in microservices mode, via `manage.py consume_gdpr` (`management/commands/consume_gdpr.py`, service name `auth`). stapel-auth calls no other module's functions.

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
