# stapel-auth — MODULE.md

Agent-facing map of this module: what it provides, its fork-free extension points, and anti-patterns. Use it to classify a desired change as **app-layer override via an extension point** vs **upstream contribution** (see `docs/stdlib-contribution-pipeline.md` and system-design §8.6 in the stapel workspace). Stapel modules never import each other; all integration goes through `stapel_core` (comm, signals, registries) and Django settings. Everything below is verifiable against the code — file references are relative to this repo.

## What this module provides

Full-featured authentication as a single pip-installable Django app (`stapel_auth`, app label `authentication`):

- **Login/registration methods** (each gated by an `AUTH_*` flag): email/phone OTP, anonymous, password (+ optional TOTP step-up), OAuth2 (9 built-in providers), enterprise SSO (SAML SP + OIDC RP, per-org DB config), email link, QR login, passkeys (WebAuthn), TOTP. Each method's UI placement (`main`/`overflow`/`bottom`) is a sibling `AUTH_*_PLACEMENT` axis; `GET /capabilities/` emits both availability and placement/interaction/icon per method, plus OTP metadata (code length, ttl, resend cooldown) so a frontend never hardcodes these.
- **Sessions**: JWT (cookie + token pair), `UserSession` tracking, revoke one/all, suspicious-session detection and revocation, login notifications (new device / suspicious IP). Refresh rotation is a compare-and-swap under a row lock, with a short grace window for the one jti it just superseded (`REFRESH_ROTATION_GRACE_SECONDS`, below) so a browser racing its own refresh is not mistaken for a replay. OAuth account links (`/oauth/links/`): connect/disconnect additional provider accounts beyond the one a user registered/logged in with.
- **Step-up verification factors** (`otp_email`, `otp_phone`, `totp`, `passkey`) registered into the `stapel_core.verification` factor registry, plus the challenge endpoints (`/verification/...`) and per-user preferences backing the `auth.verification.policy` comm function.
- **Security surface**: audit log (`AuthAuditLog`), login attempt lockout, authenticator (email/phone/TOTP) change flows — instant and delayed with day-1/7/13 notifications. TOTP instant replace (`POST /totp/setup/` with `code`/`backup_code`, proof-gated once a device is active) and delayed removal (`/totp/change/delayed/{initiate,status,cancel}/`, for a lost device — requires a verified email or phone) share the exact same `AuthenticatorChangeRequest` model and Celery tasks as phone/email; every TOTP change (instant or delayed) notifies the verified contact (`mfa.services.notify_totp_change`).
- **Passkey credential management** (`/passkey/`): list, register (begin/complete), authenticate (begin/complete), `PATCH /passkey/{id}/` to rename and `DELETE /passkey/{id}/` to retire. Both per-credential routes resolve the row through one predicate — `PasskeyViewSet._own_credential`, which filters on `(id, user=request.user, is_active=True)` — so a credential belonging to somebody else is a **404**, indistinguishable from an id that never existed (a 403 would confirm the id is real and whose it is not). Only `device_name` is writable; `aaguid`, `transports`, `created_at`, `last_used_at` and `sign_count` are what the authenticator attested or the server observed, and a rename body that names them is ignored. Renaming is management, not enrollment: an enroll-only session is refused by `DenyEnrollOnly` (only `register_complete` is on its allowlist). Every rename writes a `passkey_renamed` audit row carrying both labels.
- **Admin/service API**: service API keys, capabilities, admin user broker, admin audit log; OpenID discovery + JWKS + token introspection; nginx `auth_request` monitoring proxy (`monitoring_proxy.py`).
- **GDPR data owner** (section/owner name `auth`): the Art. 15 export lives in `gdpr.py: AuthGDPRProvider`, the Art. 17 erasure in `erasure.py: erase_subject` — one function reached both by the in-process provider (monolith registry, or `manage.py consume_gdpr` in microservices mode) and by the erasure-protocol subscribers `apps.py ready()` registers through `stapel_core.gdpr.register_gdpr_owner` (`gdpr.erasure.requested` → `gdpr.section.erased`, `gdpr.owner.probe` → `gdpr.owner.alive`, claiming subject type `account`). Auth also **hosts** stapel-gdpr, so both receipt paths run in one process for one account and exactly one receipt is written — the orchestrator's local receipt skips a part that is already done (`tests/test_gdpr_owner.py`).
- **Signup attribution** (`attribution.py`, `models.SignupAttribution`, axis `AUTH_SIGNUP_ATTRIBUTION`): every door that answers `REGISTERED` accepts an optional `attribution` object (`{click_id, click_id_type: gclid|gbraid|wbraid, captured_at, utm?}`) and stores it once against the new account — the OTP verifiers and `POST /oauth/login/` in the body, `GET /oauth/{provider}/authorize/` as flat query parameters parked in the flow state the callback already reads (the redirect flow has no body, and the identifier never travels through the provider). Stored **only when the call registers**; a login carries no new attribution, and an older `captured_at` never overwrites a newer one. Read back through `auth.signup_attribution`. Exists because browser-side conversion reporting depends on a session tie that a webmail tab, an OAuth round trip, thirty minutes or an unanswered consent banner each break silently — offline conversion import is the only channel that needs no cookie at conversion time, and the only one that can report a conversion the browser never witnessed. Storing it can never refuse an account: every write is wrapped and a failure logs instead of 500ing a sign-up.
- **Flow registry** (`flows.py`): documented business flows consumed by `stapel_core.flows` tooling.

Public package API (`stapel_auth/__init__.py`, lazy `__all__`): `auth_settings`, `PROVIDER_REGISTRY`, `BEAT_SCHEDULE` (Celery beat schedule for the delayed-change tasks, see below), the staff-role assignment services `assign_staff_role`, `revoke_staff_role`, `staff_roles_for` (admin-suite AS-2, see below), and the per-feature URL factories `get_admin_api_urls`, `get_anonymous_urls`, `get_magic_link_urls`, `get_mfa_urls`, `get_oauth_urls`, `get_openid_urls`, `get_otp_urls`, `get_password_urls`, `get_qr_urls`, `get_security_urls`, `get_sessions_urls`, `get_sso_urls`, `get_verification_urls`.

## Extension points (fork-free)

### Settings (`conf.py` — `STAPEL_AUTH = {...}` dict)

`auth_settings` is a `stapel_core.conf.AppSettings` namespace (the shared per-app settings pattern). Resolution order per key: `STAPEL_AUTH['KEY']` → flat Django setting of the same name → env var → built-in default. Env fallback is disabled (`no_env`) for secrets/trust anchors (`INTERNAL_SERVICE_KEY`, `OAUTH_PROVIDERS`), dotted-path seams (`OAUTH_PROVIDER_CLASSES`, `REREGISTRATION_MODEL`), `LEGACY_STEP_UP_GRANT_SCOPES`, `MOCK_OTP_CODE` and **every boolean gate** — env vars are strings and any non-empty string is truthy, so a stray `AUTH_PASSWORD_LOGIN=false` env var must not silently enable password login. All keys below exist in `conf.py: DEFAULTS`.

| Key | Default | What it customizes |
|---|---|---|
| `FRONTEND_URL` | `None` (env `FRONTEND_URL`) | The **primary** site's SPA base. Redirect base for SSO / magic link / QR login and the OAuth step-up `/totp-challenge` redirect; one of the `redirect_after` allowlist origins. Unset ⇒ same-origin-relative redirects. With a site registry (`STAPEL_SITES`) it is the fallback, not the answer — see *Per-host links and redirects* below |
| `BACKEND_URL` | `None` (env `BACKEND_URL`) | Absolute backend URL for SAML/OIDC endpoints and revoke-suspicious links |
| `USE_MOCK_SMS_OTP` / `USE_MOCK_EMAIL_OTP` | `False` | Mock OTP delivery (dev/test) |
| `MOCK_OTP_CODE` | `'0000'` | The accepted code in mock mode — and, on a mocked channel, the width the capabilities contract reports (see `OTP_LENGTH`) |
| `OTP_TTL` | `600` | OTP code lifetime, seconds — the single source for both the stored entry's TTL (`otp/services.py` over `stapel_core.verification.codes`) and the `capabilities.otp.ttl_seconds` contract value |
| `OTP_MAX_ATTEMPTS` | `5` | Wrong-code attempts before block. The budget lives inside the code's own store entry, so a fresh code always arrives with a fresh budget |
| `OTP_LENGTH` | `6` | Digits in a generated code (storage cap 8). Was `4` before 0.21 — a 10⁴ space that the attempt/rate caps narrow but do not enlarge. Not read directly by either consumer: `otp.services.issued_code_length(channel)` is the single source both the generation path and `capabilities.otp.{email,phone}_code_length` go through, so a mocked channel reports the width of `MOCK_OTP_CODE` instead (0.25.2) |
| `OTP_RATE_LIMIT_PER_HOUR` | `3` | OTP sends per hour per phone/email, on top of the per-send cooldown. `0` disables. Enforced since 0.21 — before that it was configured and read by nobody |
| `OTP_RESEND_COOLDOWN` | `30` | Seconds between OTP sends per phone/email/device — single source for both the rate-limit window and `capabilities.otp.resend_cooldown_seconds` |
| `MAGIC_LINK_TTL` | `900` | Magic link lifetime, seconds |
| `MAGIC_LINK_RATE_LIMIT_PER_HOUR` | `3` | Magic link sends per hour per email. `0` disables. Enforced since 0.21 — `MagicLinkService` used to carry a hardcoded 3 and ignore this key |
| `QR_TOKEN_TTL` | `300` | QR login token lifetime, seconds |
| `SESSION_TTL_DAYS` | `30` | `UserSession` expiry |
| `REFRESH_ROTATION_GRACE_SECONDS` | `10` | How long after a rotation the session's **immediately previous** refresh jti is still answerable — with the pair that rotation produced, not with a new one. Rotation is a compare-and-swap, so a page that boots while a refresh is in flight presents the superseded jti seconds later and used to be revoked as a replay, logging a legitimate user out for good (D413). Inside the window the session is neither rotated again nor revoked and the response repeats the current pair, so a racing tab converges on the winner's tokens instead of holding a doomed one; the window is measured from the rotation, never from the reuse, so replaying cannot walk it forward. Exactly one previous jti is covered: a jti two rotations back, the previous one after the window, a revoked session and a blacklisted token are all still `error.401.refresh_revoked`. `0` restores the pre-0.33 behaviour (every replay revokes). Needs a cache shared by every process serving `/token/refresh/` — the current pair lives there, keyed by the jti it replaced, for exactly this many seconds (the session row stores jtis, never tokens); with no shared cache the window degrades to the old revocation and says so at WARNING. |
| `ALLOW_UNTRACKED_REFRESH` | `False` | Whether `POST /token/refresh/` accepts a validly signed refresh token that no `UserSession` row tracks. Off: such a token is refused, so a refresh can only ever rotate a session the server knows about. On, it is a **migration aid only** — a deployment holding tokens minted before session tracking existed keeps them working until they expire, at the price of accepting any token whose jti the session table has never seen. |
| `ANONYMOUS_USER_LIFETIME_DAYS` | `30` | Anonymous account lifetime |
| `ANONYMOUS_RATE_LIMIT_PER_HOUR` | `20` | New guests one client may mint per hour at `POST /anonymous/` (`429` beyond it, `0` disables). Reusing a guest session — same `device_id` from the same client address, or the anonymous JWT already held — costs nothing |
| `AUTH_ANONYMOUS` | `True` | Anonymous (guest) auth axis: gates `POST /anonymous/` (own URL factory `get_anonymous_urls`, independent of the email/phone gates) and the `anonymous` capability |
| `AUTH_TOTP` | `True` | TOTP axis: gates the `/totp/*` endpoints in `get_mfa_urls` (passkey-style) and the `mfa.totp` capability. Step-up rides `/totp/challenge/verify/` — keep it on where step-up is on |
| `JWT_COOKIE_DOMAIN` | `None` (env) | JWT cookie domain override |
| `TOTP_ISSUER` | `'Stapel'` (env) | Issuer shown in authenticator apps |
| `WEBAUTHN_RP_ID` | `None` (env; falls back to request host) | Passkey relying-party ID |
| `WEBAUTHN_RP_NAME` | `'Stapel'` | Passkey relying-party display name |
| `WEBAUTHN_ORIGIN` | `None` (env; falls back to `FRONTEND_URL`) | Expected WebAuthn origin |
| `SSO_ENFORCED_REDIRECT_PATH` | `'/login'` | Redirect path when SSO is enforced for a domain |
| `SAML_REQUIRE_CONDITIONS` | `True` | Refuse a SAML assertion with no `Conditions`/`NotOnOrAfter` — i.e. no validity window, so it never expires |
| `SAML_REQUIRE_AUDIENCE` | `True` | Refuse a SAML assertion with no `AudienceRestriction` — one addressed to nobody in particular is one the IdP may have minted for a different SP |
| `SAML_ALLOW_IDP_INITIATED` | `False` | Accept a SAML response with no `InResponseTo`. Off: unsolicited responses correlate to no request of ours, so the single-use request-id check has nothing to bite on. Turn on only if you really run IdP-initiated SSO |
| `SSO_LINK_EXISTING_BY_EMAIL` | `False` | Let an SSO assertion claim an account that already exists here purely because the email string matches. Off: the account is claimed only through an existing `OrgMembership` or the org's configured `domain` |
| `LOGIN_NOTIFICATION_ENABLED` | `False` | New-device / suspicious-IP login alert emails |
| `REREGISTRATION_MODEL` | `'stapel_gdpr.models.ReRegistrationHash'` | **Dotted path**, resolved lazily in `gdpr.py` — stapel-gdpr is not a hard dependency; point at your own model |
| `INTERNAL_SERVICE_KEY` | `None` | Service-to-service auth key (`no_env` — set via `STAPEL_AUTH` or a flat setting, never picked up from the environment) |
| `OAUTH_PROVIDERS` | `{}` | Per-provider credentials: `{'google': {'client_id': ..., 'client_secret': ...}}` (parsed into `OAuthProviderConfig`) |
| `OAUTH_PROVIDER_CLASSES` | 9 built-ins (see below) | **Dotted-path list** of `OAuthProvider` subclasses registered at startup — append your own class to add a provider without touching this repo |
| `AUTH_PHONE_REGISTRATION` / `AUTH_EMAIL_REGISTRATION` / `AUTH_OAUTH_REGISTRATION` / `AUTH_SSO_REGISTRATION` | `True` | Registration method gates — enforced at the **account-creation site**, not at the request-a-code step, so login keeps working with registration off (see "Closing registration" below) |
| `AUTH_PASSWORD_REGISTRATION` | `False` | Password registration gate |
| `AUTH_REGISTRATION_CLOSED_BEHAVIOR` | `'silent'` | What a stranger sees on the OTP surfaces when their method's registration axis is off: `silent` (identical answer for everyone, the stranger's code is simply never delivered — no existence oracle), `request` (403 `error.403.registration_closed` at `*/request/`), `verify` (code sent, 403 at `*/verify/`). Unknown values degrade to `silent`. `no_env` |
| `AUTH_PHONE_LOGIN` / `AUTH_EMAIL_LOGIN` / `AUTH_SSO_LOGIN` / `AUTH_QR_LOGIN` / `AUTH_PASSKEY_LOGIN` / `AUTH_MAGIC_LINK_LOGIN` | `True` | Login method gates |
| `AUTH_OAUTH_LOGIN` | `True` | Gates both OAuth doors. The redirect flow (`/oauth/{provider}/authorize/` → `/callback/`) is safe by construction. **`POST /oauth/login/` — the token-body endpoint — is only safe once `OAUTH_ACCEPTED_AUDIENCES` pins which client IDs may vouch for an identity**; unpinned or unverifiable it refuses. See "The token-body OAuth endpoint" below |
| `OAUTH_ACCEPTED_AUDIENCES` | `{}` | `{provider_id: [client_id, ...]}` — the OAuth client IDs a caller-supplied access token may have been issued to. A **list**, because one project legitimately has separate client IDs per platform (Google issues distinct Web / iOS / Android IDs). Unset for a provider = its own `client_id` from `OAUTH_PROVIDERS`. `no_env` — it is the trust anchor of the token-body endpoint |
| `AUTH_PASSWORD_LOGIN` | `False` | Password login gate |
| `AUTH_LEGACY_TOKEN_LOGIN` | `False` | The deprecated `POST /token/` alias of `/password/login/`. Off: the route answers 403 (and is not mounted at all by `get_sessions_urls()`). When on it also requires `AUTH_PASSWORD_LOGIN`, and applies the same lockout and the same `PASSWORD_LOGIN_STEP_UP` challenge as the dedicated path |
| `OAUTH_STEP_UP` | `False` | TOTP challenge after OAuth login |
| `PASSWORD_LOGIN_STEP_UP` | `True` | TOTP challenge after password login |
| `FIRST_LOGIN_GATE_PATHS` | `'*'` | Which session-issuance paths the **first-login policy flags** (`password_change_required` / `mfa_enrollment_required`) block — see "The session-issuance gate" below. `'*'` = every path; or a list of `sessions.guard.SessionPath` labels (`['password', 'legacy_token']` is the narrow "password admission only" reading). `no_env` — a stray env var must not be able to narrow a security scope, and a list cannot survive the string round-trip. **`is_active=False` is refused on every path unconditionally and is not covered by this key.** |
| `AUTH_EMAIL_PLACEMENT` / `AUTH_PHONE_PLACEMENT` | `'main'` | Where the sign-in panel renders this method: `main` (inline tab) / `overflow` (behind "more") / `bottom` (bottom button row). Presentational only — never gates availability |
| `AUTH_PASSWORD_PLACEMENT` / `AUTH_MAGIC_LINK_PLACEMENT` | `'overflow'` | Same axis as above |
| `AUTH_SSO_PLACEMENT` / `AUTH_OAUTH_PLACEMENT` / `AUTH_QR_PLACEMENT` / `AUTH_PASSKEY_PLACEMENT` | `'bottom'` | Same axis as above |

The `AUTH_*` gates also drive the URL factories in `urls.py`: `include('stapel_auth.urls')` mounts everything (per-request 403 gating), or compose your own URLconf from `get_*_urls()` factories so disabled features 404.

The boolean gates above are this module's **config axes** (capability-config.md §1 in the stapel workspace root): machine-readable metadata over `STAPEL_AUTH`, published as the fourth contract artifact `docs/capabilities.json` (see below). Each factory declares its gating flags and contributed URL patterns in `urls.py: GATE_REGISTRY` via the `_gated()` helper — the declaration lives where the gating executes, so the artifact cannot drift from the code.

### The token-body OAuth endpoint — `OAUTH_ACCEPTED_AUDIENCES`

There are two OAuth login doors and they are not equally safe by construction:

| Door | Where the access token comes from | Audience |
|---|---|---|
| `/oauth/{provider}/authorize/` → `/callback/` | our own `client_secret` code exchange | ours by construction — nothing to check |
| `POST /oauth/login/` | **the request body** | whatever the caller's token was minted for |

An OAuth access token is a bearer credential scoped to the OAuth **client** it was issued to. It is not a statement about who the holder is *to us*. So the second door, left unpinned, accepts a token minted for **somebody else's app** against a victim's provider account and issues our session for the victim — a login takeover, reachable by anyone (audit F-OAUTH).

Pin the audiences, per provider, as a **list**:

```python
STAPEL_AUTH = {
    "OAUTH_PROVIDERS": {"google": {"client_id": "<web>", "client_secret": "..."}},
    "OAUTH_ACCEPTED_AUDIENCES": {
        "google": [
            "<web>.apps.googleusercontent.com",
            "<ios>.apps.googleusercontent.com",      # Google issues one client ID PER PLATFORM
            "<android>.apps.googleusercontent.com",
        ],
    },
}
```

A list, not a value, because one project legitimately owns several clients — a single-value check would refuse every native sign-in. Unset for a provider = its own `client_id`, the only audience that can be inferred.

**Which providers can actually prove it** (`OAuthProvider.verifies_audience`):

| Provider | Mechanism | Honours a multi-ID list? |
|---|---|---|
| `google` | `GET oauth2.googleapis.com/tokeninfo` → `aud` | yes — reports the owning client for any token |
| `facebook` | `GET graph.facebook.com/debug_token` → `data.app_id` (inspected with the `{app-id}\|{app-secret}` app token) | yes |
| `github` | `POST api.github.com/applications/{client_id}/token`, HTTP Basic as the app | **no** — the check authenticates *as* the app, so it only answers "is this token mine". Extra audiences need their own secrets and are refused, never silently honoured (`W010`) |
| `zoom` | none — Zoom publishes no introspection endpoint (verified 2026-08-24: `/oauth/token` and `/oauth/revoke` route, `/oauth/introspect` 404s), no third-party token verification keys, and `/users/me` proves liveness, not provenance | refuses the token-body door; redirect flow unaffected |
| `apple`, `twitter`, `yandex`, `vk`, `sber` | none — no profile call either (`get_user_data` raises `NotImplementedError`) | refuse both doors, as before |

`stapel_core.oauth.check_audience` is the gate and **every** non-proof is a refusal: no mechanism, nothing pinned, a mismatch, or an exception inside the verifier. A verification step that fails open is not a verification step.

**Boot checks** (`checks.py`), all gated on `AUTH_OAUTH_LOGIN`:

- **`W009`** — the provider cannot verify at all, so the token-body endpoint refuses it. Its redirect flow still works.
- **`E008`** — the provider *can* verify but nothing is configured to compare against, so every token is refused. An outage, and named as one.
- **`W007`** — audiences were inherited from `client_id` rather than declared. Right for one client, silently wrong the moment a second exists.
- **`W010`** — audiences are declared that this provider cannot check (the GitHub case).

### Per-host links and redirects — `stapel_auth.hosts` (0.31.0)

One image, N hosts. When the deployment declares a site registry (`STAPEL_SITES` / `STAPEL_SITES_FILE`, `stapel_core.sites`), `FRONTEND_URL` stops being the answer to "where does this link go?" — it becomes the primary site's base and the fallback. Two functions are the whole vocabulary, and they are the seam to override if a host wants different behaviour:

| Helper | Answers | Used by |
|---|---|---|
| `stapel_auth.hosts.frontend_url_for(request)` | `https://<site host>` when the request arrived on a registered host or alias, otherwise `FRONTEND_URL` | every link/redirect minted **while holding a request** |
| `stapel_auth.hosts.allowed_return_origins()` | `frozenset` of exact origins: `FRONTEND_URL`'s own origin ∪ `registry.origins()` | `redirect_after` / `return_to` validation |

Rules this module holds itself to, and that an extension must too:

- **Holding a request ⇒ `frontend_url_for(request)`.** Reading `FRONTEND_URL` there mails a person of the second brand a link to the first brand's domain — a host whose cookie jar their session does not live in.
- **No request ⇒ `FRONTEND_URL`, and say so.** Celery tasks, beat jobs and signal handlers have no `Host` header; the primary site is the deployment's default face by design. Where a task mints a *user-visible* link, resolve the base **in the view** and pass it as a task argument — `LoginNotificationService.check_and_notify(user, session, request=…)` → `evaluate_login_notification(..., frontend_url=…)` is the pattern.
- **An unmatched host keeps `FRONTEND_URL`, it is not promoted to the primary.** `site_for_request` falls back to the primary because a page needs a brand; a *link* does not, and minting one for a host the registry does not recognise is how a probe's `Host:` header ends up in an email.
- **Allowlists compare parsed origins, never prefixes.** `https://<registered>.attacker.test/` starts with a registered host and is somebody else's site. `https` only, with exactly one exception: `FRONTEND_URL`'s own scheme, so `http://localhost:3000` keeps working in development without opening `http://<registered host>/`.
- **Fleet-wide values stay fleet-wide.** `JWT_ISSUER`, `JWT_SECRET_KEY` and the session table are one per deployment, not one per brand — one account signs in on every host. The SAML/OIDC SP base (`BACKEND_URL`) is an identifier registered with the IdP and must not vary with `Host`. WebAuthn RP ID / origin still follow `FRONTEND_URL` (a per-host RP is a separate step).

`GET /<auth-prefix>/api/v1/site/` is mounted here (`get_site_bootstrap_urls`, always on, `AllowAny`, `Cache-Control: public, max-age=300`) from `stapel_core.django.sites.urls.get_site_urls()` — auth owns the mount, core owns the view, and the address is identical in every fleet so a storefront can hardcode one relative URL.

`stapel_core.sites.W001` fires when `FRONTEND_URL`'s host is not one of the registered hosts: the fallback would then point at a domain the deployment does not serve.

### Deployment requirement — the client IP behind a proxy (`STAPEL_NETINTEL['TRUSTED_PROXY_HEADER']`)

Everything this module rate-limits, locks out or writes to an audit row is keyed on the caller's IP: the guest-mint budget (`ANONYMOUS_RATE_LIMIT_PER_HOUR`), the progressive OTP lockout, and the `LoginAttempt` / `AuthAuditLog` / `UserSession` rows the user's own security screen shows. **There is exactly one place that value comes from — `stapel_core.netintel.client_ip`** (`otp/views.py: AuthViewSet.get_client_ip`, `sessions/services.py: _get_client_ip`, `mfa/views.py`, the delayed-change initiators). It trusts `REMOTE_ADDR` and nothing else until the deployment says otherwise:

```python
# settings.py — ONLY when the edge proxy overwrites this header on every request
STAPEL_NETINTEL = {"TRUSTED_PROXY_HEADER": "HTTP_X_REAL_IP"}
```

```nginx
# nginx — the header must be REPLACED, not appended to
proxy_set_header X-Real-IP $remote_addr;
```

Two rules, both load-bearing:

- **Declare the header, or every caller shares one bucket.** Behind a proxy with nothing declared, `REMOTE_ADDR` is the proxy: one rate-limit budget and one lockout counter for the whole internet, and one address in every audit row. `stapel_auth.W005` fires when the deployment has already declared it is behind a proxy (`SECURE_PROXY_SSL_HEADER`, `USE_X_FORWARDED_HOST`, `USE_X_FORWARDED_PORT`) without naming a client-IP header.
- **Never point it at a header your edge only appends to.** `client_ip` takes the FIRST element of the trusted header, which is correct only under an overwriting proxy. The common nginx recipe `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for` **appends**, so behind it the first element is client-supplied text and every IP-keyed limit, lockout and audit IP becomes forgeable by rotating one header. `stapel_auth.W006` warns whenever `TRUSTED_PROXY_HEADER` names `HTTP_X_FORWARDED_FOR`; silence it via `SILENCED_SYSTEM_CHECKS` only once you have confirmed the edge replaces the header and no later hop can prepend to it. Depth-counting (trust the Nth element from the right) is deliberately not offered — a wrong depth fails silently and open, whereas an overwritten header cannot.

Pre-0.26 this module read `X-Forwarded-For` by hand and used its leftmost element, which is the spoofable form of exactly this decision. If you extend auth, do not reintroduce it: **read the client IP through `stapel_core.netintel.client_ip`, never from `request.META` / `request.headers` directly.**

### Changing a verified email or phone requires proving the current one

`POST /email/verify/` and `POST /phone/verify/` **set** an authenticator; they do not **replace** one. With an authenticated non-anonymous session:

| Account state | `*/request/` + `*/verify/` for a new value |
|---|---|
| No verified value on that channel (or the same value) | Works, single step → `MODIFIED` |
| A different value, and the channel is verified | `403 error.403.change_requires_current` at **both** steps (no OTP is spent) |

Replacing a verified value goes through the change flow that already proves the current authenticator — `{email,phone}/change/instant/{request-old,verify-old,request-new,verify-new}/` (or the delayed 14-day strategy for a lost channel). A single OTP to the *new* address proves control of the new address only; accepting it as authority over the old one turns any live session — a stolen JWT, an unlocked phone, an XSS — into a permanent account takeover, because the attacker rewrites the recovery address without ever touching the one the owner still holds. **This has no configuration axis on purpose**: there is no deployment for which "one code to an address you chose rewrites the address you didn't" is the intended contract.

### Celery beat schedule

`tasks.py` defines three periodic tasks the **delayed** (14-day, no-old-channel-proof) authenticator-change strategy depends on end-to-end — `send_change_notifications` (day-1/7/13 emails/SMS to the old contact — or, for `change_type='totp'`, the user's current verified contact, since TOTP has no "old address"), `execute_pending_changes` (flips the email/phone, or force-disables the TOTP device, once `scheduled_at` is reached), `cleanup_expired_requests` (marks >30-day abandoned requests `EXPIRED`). No new beat entry was needed for TOTP — it reuses these same three tasks by `change_type`. Installing this app does **not** wire a host's `celery.py` — with no beat entry, a `PENDING` delayed change just sits there forever: no notifications, and it never applies. This is a fork-free extension point the same way OAuth providers and verification factors are: a **discoverability + documentation** contract, not auto-wiring (auto-editing a host's celery config is a scaffold concern, out of scope for a library).

`stapel_auth.BEAT_SCHEDULE` (also importable as `stapel_auth.tasks.BEAT_SCHEDULE`) is the single source of truth for the three task names + intervals — merge it into your own `CELERY_BEAT_SCHEDULE`:

```python
# celery.py (or wherever your project defines CELERY_BEAT_SCHEDULE)
from stapel_auth import BEAT_SCHEDULE as AUTH_BEAT_SCHEDULE

app.conf.beat_schedule = {
    **app.conf.beat_schedule,  # your own project's periodic tasks, if any
    **AUTH_BEAT_SCHEDULE,
}
```

| Task | Interval | Why |
|---|---|---|
| `send_change_notifications` | hourly | Cheap query; keeps day-1/7/13 notifications from lagging a full day behind the actual threshold |
| `execute_pending_changes` | every 5 min | This is what applies the change at `scheduled_at` — a coarser interval leaves it applied-but-not-yet-executed for longer |
| `cleanup_expired_requests` | daily | Pure bookkeeping; nothing time-sensitive depends on it running sooner |

The **instant** strategy (old-channel OTP proof, applied synchronously in the request) does not depend on beat at all — only the delayed strategy does.

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
| `user.registered` | `{user_id, auth_type, email, avatar_url}` (`events.py: UserRegisteredPayload`) — `avatar_url` is `User.avatar` (OAuth only today), `null` otherwise | First successful auth of a new account (`otp/views.py: _notify_user_registered`) — profile/workspace creation is done by subscribers |
| `user.created` | the JWT claim set: `{user_id, username, email, phone?, auth_type?, is_anonymous?, is_staff, is_superuser, is_active, staff_roles?}` (`events.py: UserProjectionPayload`) | An identity row was born, whoever wrote it — a `post_save` observer (`user_projection.py`), not a call site. See **The user projection** below |
| `user.updated` | same payload (the full claim set, not a delta) | A projected field of an existing row really changed. A re-save with no change, and any write whose `update_fields` cannot touch a projected field, emit nothing |
| `user.merged` | `{from_user_id, into_user_id, reason}` (`events.py: UserMergedPayload`) | A guest account was folded into an existing one on sign-in and the guest row DELETED (`otp/services.py: merge_anonymous_into`). Consumers re-parent every row they own from `from_user_id` onto `into_user_id`, idempotently — the opposite instruction to `user.deleted` on the same tables, which is why `stapel_core.lifecycle.E001` fails an app that answers only the delete half. Emitted in the same transaction as the ledger row and the delete. `reason` is `anonymous_promotion` on every path today: it does not distinguish them, and `UserMerge.source` is where that distinction is kept |
| `user.session_created` | `{user_id, session_id, device_type, ip_address, created_at}` | Schema declared; **no `emit()` call in code yet** (see gaps) |
| `user.session_revoked` | schema in `schemas/emits/` | Schema declared; **no `emit()` call in code yet** (see gaps) |
| `staff.role.assigned` | `{user_id, role, staff_roles, actor_id}` (`events.py: StaffRoleAssignedPayload`; `staff_roles` = full list **after** the change) | A staff role was assigned (`staff_roles.py: assign_staff_role` — admin, API, or direct service call). Audit stream for eventstore/notifications (admin-suite §3.8) |
| `staff.role.revoked` | `{user_id, role, staff_roles, actor_id}` (`events.py: StaffRoleRevokedPayload`) | A staff role was revoked (`staff_roles.py: revoke_staff_role`) |
| `user.deactivated` | `{user_id, reason?, actor_id?}` (`events.py: UserDeactivatedPayload`) | The account's `is_active` really went `True → False` — administrative, **reversible**, **not** a GDPR erasure. Emitted by the observer in `activation.py`, so the admin checkbox and a management shell announce it too; re-saving an already-deactivated user emits nothing |
| `user.reactivated` | `{user_id, actor_id?}` (`events.py: UserReactivatedPayload`) | `is_active` went `False → True`. Mandatory mirror: a consumer that suspended state on `user.deactivated` lifts it here |
| `gdpr.section.erased` | `{owner: "auth", subject_type, subject_key, correlation_id, receipt_id, counts}` | The erasure receipt, emitted **inside the erase's transaction** by the subscriber `register_gdpr_owner` built (`erasure.py`). `receipt_id` is derived (`auth:account:<key>:<correlation_id>`), so a redelivery mints the same one |
| `gdpr.owner.alive` | `{owner: "auth", subject_types: ["account"], correlation_id}` | Answer to `gdpr.owner.probe`, from the same subscriber that erases — which is what makes it evidence the erasure path is *consumed*. Until 0.25.0 nothing answered and owners-health read `auth: alive=false` |
| `notification.requested` | via `stapel_core.notifications.request_notification` | All outbound mail/SMS: types `otp_code`, `magic_link_login`, `new_device_login`, `suspicious_login`, `all_sessions_revoked`, `welcome`, `auth_change_requested` / `_reminder` / `_urgent` / `_completed`. Templates live in the notifications service — copy changes are **not** an auth fork |

Provided functions (`functions.py`, registered in `ready()`; schema in `schemas/functions/`):

| Function | Payload → Result | Consumer |
|---|---|---|
| `auth.verification.policy` | `{user_id}` → `{disabled_scopes, enabled_scopes}` | `stapel_core.verification.policy.get_user_policy` (cached core-side) |
| `auth.provision_user` | `{username, password?, email?, display_name?, first_login_policies[]}` → `{user_id, generated_password?}` \| `{error}` | stapel-workspaces `POST <ws>/members/provision`. `first_login_policies` is a **set of independent demands** since 0.17.0 (#90) — `password_change` and `mfa_enroll` compose; the old single `first_login_policy` string cleared whichever flag it did not name. The singular key is still read when the plural one is absent (deprecated). Neither key present is a structured 400, not an empty set |
| `auth.apply_first_login_policies` | `{user_id, policies[]}` → `{applied[]}` \| `{error}` | stapel-workspaces invitation accept, applying the org's `provisioned_user_policies` (0.17.0, #90). **Additive, never subtractive**: the flags are per-ACCOUNT while the callers are per-ORG, so subtraction would let one tenant lower another's bar. A policy already outstanding, or an `mfa_enroll` against an account that already carries a strong factor, is skipped and not reported as applied |
| `auth.mfa_status` | `{user_id}` → `{has_strong_mfa, factors[]}` | stapel-workspaces `require_mfa` enforcement sweep |
| `auth.admin_reset_password` | `{user_id, password?, first_login_policies?, actor_id?, reason?}` → `{generated_password?, sessions_revoked, first_login_policies_applied[]}` \| `{error}` | stapel-workspaces `POST <ws>/members/<uid>/password/reset` (0.18.0, #110). Everything that makes a reset safe lives behind this Function rather than in the caller: the target's sessions are revoked (a reset that leaves them standing recovers nothing), the new password is temporary by construction (`first_login_policies` defaults to `['password_change']`), and the ordering actor lands on `AuthAuditLog` (`via: admin_reset`). A **staff/superuser target is refused** with `error.403.privileged_account` — org administrator is a role inside one workspace, staff is a role over the deployment, and the first must never be a route to the second; the caller does not know who is staff, so the boundary is held here |
| `auth.resolve_merged_user` | `{user_id}` → `{user_id, merged, merged_at, source}` | Any consumer reconciling ids it holds against the merge ledger. `user.merged` is the instruction and this is the **record**: a service deployed after a merge never saw the event, a consumer whose handler was broken while it aged out of the stream cannot ask what it missed, and the guest row — the only other place the mapping lived — was deleted in the merge's own transaction. Follows the whole chain, not one hop (a guest merged into an account that was itself later merged returns the END), and an id that was never merged comes back unchanged with `merged: false`, so it is safe to call on every id rather than only suspected ones |
| `auth.issue_login_grant` | `{email, verified_email?, create_if_missing?, language?}` → `{grant_token}` | stapel-workspaces invitation claim (unregistered invitee). The token is a credential — never logged |
| `auth.signup_attribution` | `{user_id}` → `{user_id, click_id, click_id_type, captured_at, utm{}, created_at, updated_at}` \| `null` | Whatever knows an account became a paying one (billing, a subscription job), reporting that conversion offline to the ad platform weeks after the browser that produced the click is gone. A Function and not an endpoint on purpose: the caller is a service, and a front end has no use for the click identifier and every reason not to hold it. `null` is the **ordinary** answer — most accounts have no attribution — and must be read as "nothing to upload", never as "look it up somewhere else"; an unparseable `user_id` answers `null` too, so an unknown id cannot look like an outage |

Consumed events (schemas in `schemas/consumes/`, documentation — the authoritative copy is the emitter's): `gdpr.erasure.requested` and `gdpr.owner.probe`, plus the deprecated `user.deleted` (stapel-gdpr emits it beside the request until its 0.6.0 and it runs the same `erase_subject`, so deleting the handler deletes no erasure logic) — subscribed unconditionally in `ready()`, in every mode. Also `gdpr.export.requested` / `gdpr.delete.requested`, only in microservices mode, via `manage.py consume_gdpr` (`management/commands/consume_gdpr.py`, service name `auth`). stapel-auth calls no other module's functions.

### The user projection — the seam for services that FK users

**The problem it solves.** Every Stapel service keeps its own `users` rows,
and until now they were filled from exactly one place: `JWT_CREATE_USERS_FROM_TOKEN`
in `stapel_core.django.jwt.utils`, which materialises a row for *the subject
of the token being verified*. One user per request — the one holding the
token. A flow that **names a second user the service has never seen** has
nothing to hang a foreign key on: stapel-chat's `participant_ids` (a buyer
opening a thread with a seller who has never opened chat), an assignee, a
recipient, a mention. The insert dies on a foreign key violation and a
well-formed request gets a bare 500.

**The shape.** Not "let every service invent a user row when it needs one" —
that is N silent mirrors with N different truths, and the mirror outlives
the account it copied. The owner publishes the fact once and consumers
project it: `user.created` / `user.updated`, through the transactional
outbox, applied by a component this module ships.

| Half | Where | What it is |
|---|---|---|
| Owner (emit) | `user_projection.py`, wired in `AppConfig.ready` | A `pre_save`/`post_save` pair on `AUTH_USER_MODEL`. Every birth path announces — OTP verify, password register, OAuth resolve, SSO, `auth.provision_user`, the login-grant mint, `POST /anonymous/`, `POST /admin-users/`, and a host's own `createsuperuser`, data migration or shell |
| Consumer (apply) | `stapel_auth.projection` — a Django app with **no models and no migrations** | `@on_action("user.created"/"user.updated")` handlers that upsert the local shadow row |

Installing the consumer in a service:

```python
INSTALLED_APPS = [
    ...,
    "stapel_auth.projection",   # NOT "stapel_auth" — no auth tables land here
]
```

and nothing else: the two topics are ordinary Actions, so the service's
existing `manage.py consume_actions` worker picks them up. The handler is
inert wherever `JWT_CREATE_USERS_FROM_TOKEN` is `False`, which is precisely
how the identity owner already declares "my `users` table is the original,
not a copy" — installing the app there is a no-op rather than a duplicate
writer.

**Why the two writers cannot diverge.** The payload is not a designed field
list. It is `stapel_core.django.jwt.utils.serialize_user_to_jwt_data(user)`
verbatim — the same function that builds the claims a shadow row is
otherwise made from — and the consumer applies it with
`get_or_create_user_from_jwt`, the same function the JWT middleware applies a
token with. Token-driven creation and event-driven creation are *the same two
functions reached two ways*; a claim added to one is a claim added to both,
and `schemas/emits/user.created.json` is `additionalProperties: false` so a
claim added without the schema fails every emit immediately.

**Idempotency** falls out of the same choice: `get_or_create_user_from_jwt`
is a get-or-create that field-syncs an existing row, so a redelivered event,
a full replay, and a row this service already minted from a JWT all end in
one row with the same values.

**Backfill.** The observer only sees writes made after it is installed, so
accounts that predate the release are invisible to a consumer's table — the
difference between "new users can be named in a chat" and "users can be named
in a chat". Run `manage.py emit_user_projection` in the identity owner once
the consumers are listening (`--since`, `--dry-run`; `user_projection.replay()`
programmatically). It is also the repair for a `QuerySet.update()`, the one
write model signals cannot see.

**Outbox discipline, not best-effort.** `user.registered` is a milestone and
is swallowed on failure — a signup must not depend on a listener.
`user.created` is the opposite kind of fact: foreign keys resolve against it,
so it commits with its row or not at all. That couples the user write to a
*database* write, not to a broker: the outbox row lands in the same
transaction, and delivery is somebody else's retry.

**Not the `Projection` primitive.** `stapel_core.comm.Projection` materialises
a read-only `ProjectionModel` side table. A shadow user row is not a read
model — it is the row other tables' foreign keys point at — so this seam
writes `AUTH_USER_MODEL` directly and takes its idempotency from the
get-or-create instead of a sequence column.

**Deletion is not here.** An erased account is announced by `user.deleted`
(stapel-gdpr) with its own consumers; `user.updated` carrying `is_active:
false` is a suspension, and the two must never be conflated (see below).

### Account activation — `active` / `suspended` / `deleted` (#92)

`activation.py` owns the administrative deactivate/reactivate seam and keeps
three states that must never be spelled the same way apart:

| State | Mechanism | Reversible | Announced by |
|---|---|---|---|
| `active` | `is_active=True` | — | — |
| `suspended` | `is_active=False` — the session guard refuses admission on all 19 issuance paths (0.15.0) | **yes**, nothing is destroyed | `user.deactivated` |
| `deleted` | GDPR erasure (`erasure.py: erase_subject`) — rows removed | no | `gdpr.erasure.requested` / `user.deleted` (gdpr module) |

`user.deactivated` is **not** a rename of `user.deleted`: consumers must
*suspend*, never delete, and must undo on `user.reactivated`.

**Services** (exported lazily from the package root):
`deactivate_user(user, reason=None, actor=None)` /
`reactivate_user(user, actor=None)` — both return `True` only on a real
transition, both open the transaction that makes the emit atomic with the
write. `is_deactivated(user)` delegates to
`sessions.guard.account_disabled_error`, the same predicate the issuance
paths gate on, so this module and the guard cannot drift.

**Emission is by observer, not by call site.** `is_active` is a plain field
with a checkbox in every admin, so the `pre_save`/`post_save` pair in
`activation.py` (wired in `AppConfig.ready`) watches the real transition —
the service functions, the admin, and a management shell all announce
exactly once, and a no-op re-save announces nothing. Two documented blind
spots: `QuerySet.update()`/`bulk_update` bypass model signals (use
`deactivate_user`), and a bare field flip carries no `reason`/`actor` (both
payload fields are optional for exactly that reason).

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

- **`@access.ops`** (read-only journal, view=HIGH): `LoginAttempt`, `AuthAuditLog`
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

### The session-issuance gate (`sessions/guard.py`)

Not an extension point so much as an **invariant with one place that holds it** — read this before adding any code path that hands out a session.

Every path that mints a *full* session funnels through `sessions.views._issue_session_tokens(user, request, *, path, audit_event)`. That function is the choke-point, and it is where admission is decided:

- **`is_active=False` → refused everywhere, unconditionally.** No next step exists, the refusal is final (`401 error.401.account_disabled`), and the body deliberately carries no account detail — it must not become an account-enumeration oracle.
- **First-login policy flags** (`password_change_required` / `mfa_enrollment_required`, raised by `auth.provision_user` / `auth.apply_first_login_policies`; INDEPENDENT since 0.17.0 — an org may demand both, and the login flow chains forced-change → mfa-enrol) → refused **with a next step**: the denial carries a freshly minted `challenge_token` plus a `requires` label, so the client can send the user to `POST /password/forced-change/` or `POST /mfa/enroll/exchange/`. A flag must never produce a dead 403 — otherwise a flagged user who arrived by magic link is locked out permanently (`/password/forced-change/` never asks for the old password, which is what makes the wide default humane). Scope is configurable via `FIRST_LOGIN_GATE_PATHS`; the default `'*'` treats a flag as "a mandatory step before ANY admission".

The gate is deliberately **not** inside `create_tokens_for_user`: that primitive is shared with the *intermediate* paths (forced change, the enroll-only exchange), which must stay outside the invariant or the user can never complete the very step they are held on. Password **reset** is not one of them: proving control of a mailbox replaces a password, it does not decide admission, so `/password/reset/{email,phone}/verify/` goes through the gate on `SessionPath.PASSWORD_RESET` like any other login.

Mechanics you have to respect when adding a path:

| Concern | Rule |
|---|---|
| Labels | Add a `SessionPath` constant and pass `path=SessionPath.X`. An undeclared caller **fails closed** (always gated). |
| JSON paths | Nothing to do. `SessionIssuanceDenied` subclasses `StapelServiceError`, so the stapel-core DRF handler renders it identically everywhere — no per-caller `try/except`. The next step arrives in `params` (`requires`, `challenge_token`, `expires_in`). |
| Browser-redirect paths | Magic link, the OAuth callback, QR session-share and the SSO ACS answer a *navigation*: they catch `SessionIssuanceDenied` and redirect to `denial_redirect_url(...)` → `{FRONTEND_URL}/login?first_login=<requires>&challenge_token=<tok>&next=<n>` (or `?error=account_disabled` when there is no next step). A raw JSON error body in the address bar is not a recoverable flow. |
| Minting around the gate | Don't. `tests/test_session_issuance_gate.py` walks the AST and fails on any `create_tokens_for_user` caller that is neither inside the minter nor on an explicit, reason-annotated bypass roster. The roster records a *declared* intention, not a verified one — it protects against an unnoticed bypass, not a wrong one. |

### Closing registration (`registration.py`)

The sibling invariant of the session gate above, and the same shape: **one place decides whether a NEW account may be born.**

`AUTH_<METHOD>_REGISTRATION` is enforced at the creation site — not at the request-a-code step, where it used to sit reading `not LOGIN and not REGISTRATION` (an `and`, so it fired only when the whole channel was off; with login on and registration off the endpoint accepted any address and `email_verify` created the user unconditionally). Every creation site now goes through `registration.require_registration_open(method)` / `registration_open(method)`: OTP email/phone (fresh account **and** guest promotion), `_resolve_oauth_user` (both the promote and the create branch), and SSO JIT provisioning.

**Not gated, on purpose** — these are the owner's doors, and a deployment with all axes off and no owner path would have no way to create accounts at all:

| Path | Why it stays open |
|---|---|
| `auth.provision_user` (comm) | The canonical "only the owner makes accounts" surface — namespaced logins handed out by an org |
| `POST /admin-users/` | Service API key or staff only |
| `LoginGrantService.exchange(create_if_missing=True)` | The grant is minted server-side by a trusted issuer (workspaces invites), never by the person signing in; `AUTH_LOGIN_GRANT` is off by default |
| `POST /anonymous/` | A guest session is not an account — its own `AUTH_ANONYMOUS` axis. *Promoting* a guest into a real account IS registration and IS gated |

**The oracle.** Refusing only *unknown* addresses turns the OTP endpoints into an account-existence oracle, so the tradeoff is a setting (`AUTH_REGISTRATION_CLOSED_BEHAVIOR`), not a rewrite: `silent` (default) answers everyone identically and never delivers the stranger's code — the record, the cooldown and the block state are all created exactly as for a member, so even the 429 is not a side channel; `request` refuses at `*/request/` (usable, fully enumerable); `verify` sends the code and refuses at `*/verify/` (enumerable *and* mails strangers). OAuth and SSO refuse a fresh identity outright — there is nothing to enumerate when the caller must already control the provider account.

To close sign-up on a deployment: set the four/five `AUTH_*_REGISTRATION` axes to `False` and create accounts through `auth.provision_user` (or `/admin-users/`). `GET /capabilities/` already reports each method's `can_register`, so the frontend hides the sign-up surface without further work.

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
- **Don't mint a session outside `_issue_session_tokens`.** Calling `create_tokens_for_user` (or `TokenService`) directly in a new login path re-opens the exact hole `sessions/guard.py` closes — an account that is deactivated or owes a first-login step walks straight in. Route it through the minter with a `SessionPath` label. If it genuinely resolves an intermediate, say so on the bypass roster in `tests/test_session_issuance_gate.py`; the roster is what turns "we remember which bypasses are legitimate" into a failing build.
- **Don't consume `PROVIDER_REGISTRY` mutation as an API.** It is exposed for tests; the supported mutation path is `register_provider` / settings.
- **Don't reference the concrete user class.** Always `get_user_model()` / `settings.AUTH_USER_MODEL` (the module itself follows this rule everywhere).
- **Don't read the client IP from `request.META` / `request.headers`.** `X-Forwarded-For` and friends are caller-supplied unless a trusted edge overwrites them, and this module keys rate limits, lockouts and audit rows on that value. Go through `stapel_core.netintel.client_ip`; a deployment declares its proxy once via `STAPEL_NETINTEL['TRUSTED_PROXY_HEADER']` (see above).
- **Don't resolve an identity from a token you did not mint without pinning its audience.** `OAuthService.get_user_data` runs the check; only the authorization-code callback may pass `token_is_ours=True`, and only because it exchanged the token itself. A new provider that cannot introspect keeps `verifies_audience = False` — looking verified while not being verified is worse than plainly refusing.
- **Don't let a code sent to a new address overwrite a verified one.** Setting a first email/phone is one step; replacing a verified one goes through the change flow that proves the current authenticator. A new-address OTP is not authority over the old address (see above).

## App-layer override vs upstream contribution — rule of thumb

**App-layer** (stays in your project, your property): anything expressible through the tables above — a settings value or feature flag, a new OAuth provider class, a new verification factor, a swapped serializer on a subclassed view, a custom user model, a `user_registered` signal receiver or `user.registered` subscriber, notification template copy, a custom `REREGISTRATION_MODEL`, your own URLconf composition. Test: *does the change fit an existing seam without editing files in `stapel_auth/`?* If yes — it is an override, never a fork.

**Upstream contribution** (belongs in this repo, via the contribution pipeline — `contrib_open`, review origin, PyPI release): bug fixes; schema changes to auth-owned models/migrations; new endpoints or flows; a *missing seam* (e.g. serializer seams for `security/`, `sso_views.py`, `admin/`, `openid/` views; actually emitting the declared `user.session_created` / `user.session_revoked` events; a new generic setting). Test: *is the change generic — would other Stapel hosts want it, and does it require editing this repo?* If yes — contribute upstream; while the release is pending, consume the beta via the artifact channel, never a long-lived fork.

**Neither** (client-specific, un-mergeable): keep it in your app layer as an override built on the nearest seam; if no seam exists, the upstream contribution is *adding the seam*, and the specific behavior stays yours.
