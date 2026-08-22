# Changelog

## [Unreleased]

## [0.24.0] — 2026-08-22

### Added — the user projection: a service can now hold a row for a user it has never met

Every Stapel service keeps its own `users` table, and until now exactly one
thing filled it: `JWT_CREATE_USERS_FROM_TOKEN`, which materialises a row for
*the subject of the token being verified*. One user per request — the one
holding the token. Any flow that **names a second user the service has never
seen** therefore had nothing to hang a foreign key on. stapel-chat's
`participant_ids` is the case that surfaced it: a buyer opening a thread with
a seller who has never opened chat inserts a `ConversationParticipant` whose
`user_id` matches no local row, the insert dies on a foreign key violation,
and a well-formed request gets a bare 500. The same hole is under every
assignee, recipient and mention in the fleet.

The fix is an owner-emitted projection, not N services inventing user rows on
demand (that is the same disease with more mirrors, each with its own truth,
each outliving the account it copied). Auth now publishes its identity rows
as facts, and ships the consumer that applies them:

- **`user.created` / `user.updated`** (`events.py: UserProjectionPayload`,
  `schemas/emits/`), emitted through the transactional outbox by a
  `pre_save`/`post_save` observer on `AUTH_USER_MODEL` (`user_projection.py`,
  wired in `AppConfig.ready`). By observer and not by call site because a
  user row is born in at least eight places here — OTP verify, password
  register, OAuth resolve, SSO, `auth.provision_user`, the login-grant mint,
  `POST /anonymous/`, `POST /admin-users/` — plus every host's own
  `createsuperuser`, data migration and management shell. A fact stream that
  foreign keys depend on cannot be maintained by remembering to call
  something. A re-save that changes nothing, and any write whose
  `update_fields` cannot touch a projected field (`update_last_login`, the
  hottest write in the module), emit nothing and cost no query.

- **`stapel_auth.projection`** — the consumer, a Django app with no models
  and no migrations that a service adds to `INSTALLED_APPS` (the app, never
  `stapel_auth` itself, so no auth tables land in a consumer's database).
  The two topics are ordinary Actions, so an existing `manage.py
  consume_actions` worker picks them up with nothing new to run. The handler
  is inert wherever `JWT_CREATE_USERS_FROM_TOKEN` is `False` — the switch by
  which the identity owner already declares that its `users` table is the
  original, not a copy.

What keeps the two writers from drifting is that they are the same two
functions. The payload is `serialize_user_to_jwt_data(user)` verbatim — the
function that builds the claims a shadow row is otherwise made from — and the
consumer applies it with `get_or_create_user_from_jwt`, the function the JWT
middleware applies a token with. Adding a claim to one adds it to both, and
the schemas are `additionalProperties: false` so adding one to neither fails
loudly at the first emit. Idempotency comes from the same place: the
materializer is a get-or-create that field-syncs, so a redelivered event, a
full replay, and a row this service already minted from a JWT all end in one
row with the same values.

- **`manage.py emit_user_projection`** (`--since`, `--dry-run`;
  `user_projection.replay()` programmatically) re-announces existing accounts
  as `user.created`. The observer only sees writes made after it exists, so
  without this the fix would read "*new* users can be named in a chat". It is
  also the repair for a `QuerySet.update()`, the one write model signals
  cannot see.

Unlike `user.registered` — a milestone, deliberately swallowed on failure so
a signup never depends on a listener — `user.created` commits with its row or
not at all: an account whose birth nobody recorded is exactly the silent
defect this closes. That couples the user write to a *database* write, not to
a broker; the outbox row lands in the same transaction and delivery is
somebody else's retry.

`user.updated` carrying `is_active: false` is a suspension and never an
erasure: `user.deactivated`/`user.reactivated` (#92) still carry the
administrative transition, and GDPR removal is still `user.deleted`. Deletion
is not part of this stream.

## [0.23.0] — 2026-08-17

### Fixed — the device a QR signs in could not use what it was handed

`GET /qr/{key}/status/` answered a fulfilled `login_request` with a JSON token
pair and nothing else. That is enough for a native/bearer caller and useless to
a cookie-mode browser front end — `@stapel/auth-react`'s default, where the
client attaches no bearer header at all by contract. Such a front end received
a real grant it could not spend on a single subsequent request: its own user
lookup went out with no credential, was refused, and the delivered session was
dropped without a word on either device. Every other flow that signs a browser
in over a plain response sets the JWT cookies (`/qr/{key}/scan/`, magic link,
SSO, OAuth); this one now does too, plus the non-httponly `stapel_auth_hint`
that accompanies every cookie-minted session. The JSON pair is unchanged, so
bearer callers see no difference.

The same handler recorded the polling device's session inside a bare
`except Exception: pass`. A session row or audit line that fails to write is a
real failure of that request; it is now logged (`logger.exception`) instead of
being unfindable afterwards.

### Fixed — the two halves of `/qr/{key}/scan/` named two different sign-in pages

A `login_request` scanned by a browser with no session redirected to
`/sign-in?redirect=…`, while the account-conflict branch of the same view — and
the sign-in route the pair's own nav manifest declares (`@stapel/auth-react`'s
`auth.login`) — say `/login`. One of the two was therefore always a
fall-through into whatever the host's catch-all does, and a redirect to a route
that does not exist fails nowhere, so it stayed quiet. Both halves now name
`/login`. Hosts that really do serve the sign-in screen at `/sign-in` need a
redirect from it, or the route renamed.

## [0.22.1] — 2026-08-16

### Fixed — the suite CI runs and the suite we run were two different suites

`0.22.0` was green here and red in CI: 18 failures, all of them the shape of
state carried between tests — a `429` where a `200` belonged, a stale-code
`MISMATCH` where `NOT_FOUND` belonged, a `change_token` that was never minted.
Nothing was wrong with the codes. The autouse fixture that empties the cache
around every test lived in the repo-root `conftest.py`, and CI runs
`pytest --pyargs stapel_auth.tests`, where collection is rooted at the *package*
directory: test node ids start at `test_*.py`, the repo root is not an ancestor
of any of them, and its fixtures reach nothing. The file is still imported,
which is what kept the hole quiet.

That mattered here and not before because `0.22.0` is the release that moved
one-time codes out of their tables and into the cache-backed TTL store. The
database rolls back between tests; the cache does not. The move turned a
harmless asymmetry into eighteen failures.

The harness now lives in `tests/conftest.py`, the one conftest both invocation
styles load, and the root file is a path-only shim with no definitions at all —
`tests/test_harness_isolation.py` fails if anything is added back to it. Two
further consequences of the same split are closed with it: `ROOT_URLCONF`
depended on which `pytest_configure` won a race (bare vs mounted urlconf), and
the `sys.path` de-shadowing that keeps `import openid` off the repo-local
`openid/` directory now runs where it is needed rather than relying on that
race. No library code changed.

## [0.22.0] — 2026-08-16

### Removed — the OTP tables; codes live in a TTL store

`PhoneVerification` and `EmailVerification` are gone, along with their tables,
their admin pages and `SecurityService.cleanup_expired_verifications`. One-time
codes now live in `stapel_core.verification.codes.OneTimeCodeStore` (core
0.28.0, the new floor): hashed, TTL-scoped, and swept by nothing because
nothing accumulates.

The tables were wrong in two ways. They held the code **verbatim**, so one read
of that table — a dump, a backup, a support query, an injection elsewhere —
authenticated as any account with a pending code. And they held it **after it
stopped meaning anything**, which is why they needed a sweeper: a job a host
merges into its own beat schedule, or forgets to. Migration `0019` drops both.
No data migration is owed and none is offered: every row is a one-time code
with a ten-minute life, so the set worth carrying is empty before any deploy
finishes.

### Changed — absence and wrongness are different facts

Presenting a code with nothing waiting for it used to answer `invalid_code`.
It now answers `error.400.code_expired`, reworded to say what actually
happened: **"The wait for your code expired. Please sign in again."** An
expired wait is not a refusal, it is an invitation to start over, and
rendering it as "invalid code" tells a user they made a mistake when the
system merely stopped waiting. This also covers the case a cache restart
produces — Redis is not durable, every pending code dies with it, and the
message is already true for that too.

The email path spent a hardcoded **7** guesses while `OTP_MAX_ATTEMPTS` said
5; both paths now read the setting. The resend cooldown and
`OTP_RATE_LIMIT_PER_HOUR` moved to the store with their semantics intact (the
hourly window still rolls; it is not a bucket that resets on the hour), and
the attempt budget now lives *inside* the code's own entry, so a fresh code
always arrives with a fresh budget and a spent budget cannot outlive the code
it killed.

### Added — `error.503.verification_unavailable`

The login path fails **closed** when the store cannot answer, and says so:
*"We could not check your sign-in right now. Please try again in a moment."*
It is returned by the OTP verify endpoints and by `LockoutService.check`,
which previously let a cache outage escape as an unhandled 500. Neither may
render as a wrong code or a lockout: an unanswerable question has no verdict
in it, and "we could not ask" is not "you may not".

## [0.21.1] — 2026-08-15

### Changed — `stapel-core` floor raised to 0.26.0

`docs/errors.json` carries an `owner` per entry, and only stapel-core 0.26.0
emits it. The floor stayed at `>=0.24.0`, so a consumer resolving an older
core regenerated an artifact without `owner` and the drift gate went red —
the field was declared but never required. The floor now matches the
artifact that is committed.

## [0.21.0] — 2026-08-14

### Changed — the gdpr error rows come from their owner now

`stapel-gdpr` 0.4.0 ships `translations/errors.{ru,es}.json` for the ten
`error.*.gdpr.*` keys it owns, so this module stops carrying a copy of seven of
them and reads all ten from the owner instead:

* `translations/errors.{ru,es}.json` lose the seven pre-ownership-scoping gdpr
  entries (byte-identical to what the owner now publishes — the `foreign`
  finding `check_translation_catalogs` raises the day the owner ships the
  language), and `translations/.state.json` loses their provenance rows.
* `docs/errors.{en,ru,es}.md` grow from 127 to 130 rows: the co-mounted
  registry gained `error.403.gdpr.account_closed`,
  `error.410.gdpr.download_consumed` and `error.503.gdpr.closure_unavailable`
  in the 2026-08-11 GDPR wave. They render in Russian and Spanish rather than
  as `_(en)_` fallbacks because stapel-translate 0.6.1 added those three
  strings to the curated builtin corpus and the owner seeded its catalog from
  it.

No behavior change here: the runtime already merged every installed app's
catalog, so only the reference doc and the write-side duplication move.

### Changed — requires stapel-core >= 0.24.0

The floor moved from `0.23.1` to `0.24.0`. It is a hard floor, not a courtesy
bump: the AUTH-01 fix lives in core (`EmailAuthBackend` compares the secret
instead of resolving a user by email), and the regression gate shipped here
imports `stapel_core.django.auth_backend_checks`, a module that does not exist
before 0.24.0. Installing this release against an older core fails at import,
which is the honest outcome — an older core is the vulnerable one.

Two of core's moved defaults reached into this module, and both are fixed here
rather than pinned around:

* **The `stapel_auth_hint` cookie was left non-Secure next to a Secure refresh
  cookie.** `hint_cookie.py` kept its own copy of core's cookie defaults
  (`JWT_COOKIE_SECURE`, fallback `False`); core 0.24.0 turned that setting on
  by default, so a deployment that never declared it started sending a
  TLS-only session cookie accompanied by a hint cookie readable over plain
  HTTP — precisely what the module promises cannot happen. The attributes are
  now read off the refresh cookie already on the response instead of being
  re-derived, so the promise is structural and no future default can split the
  pair again. `httponly=False` stays the one deliberate difference.
* **Comm payload schemas are enforced by default** (`STAPEL_COMM`
  `VALIDATE_SCHEMAS` used to follow `settings.DEBUG`). A malformed
  `first_login_policies` — a bare string, an unknown member — is therefore
  refused at the comm boundary and never reaches `auth.provision_user`,
  `auth.apply_first_login_policies` or `auth.admin_reset_password`. The
  handlers' own guards still hold for a deployment that opts out, so the
  suite now pins both layers: the schema refusal, and the structured
  `{"error": error.400.bad_request}` with validation off.

### Security — permissive defaults closed (upgrade notes)

Every item below changes a DEFAULT. The safe value is now what you get without
saying anything; the permissive value is available, but only as an explicit
act. Read this section before upgrading a running deployment.

**`POST /token/` no longer bypasses the password-login gate, the TOTP step-up
and the lockout counter.** The legacy token endpoint was registered with an
empty gate tuple ("always on") and its view consulted no setting, so it served
the same credential trade as `POST /password/login/` while ignoring all three
answers that path respects: `AUTH_PASSWORD_LOGIN` (`False` on stock defaults —
a deployment that never turned password login on had it fully open here),
`PASSWORD_LOGIN_STEP_UP` (`True` — the dedicated path mints a TOTP challenge,
this one minted the session, an MFA bypass for every TOTP-enabled account) and
`LockoutService` (no counter, no throttle, no captcha — an unlimited
password-guessing oracle).

* **New setting `STAPEL_AUTH['AUTH_LEGACY_TOKEN_LOGIN']`, default `False`.**
  While it is off, `POST /token/` answers `403`. To keep the endpoint, set it
  to `True` **and** keep `AUTH_PASSWORD_LOGIN` on — the alias is refused
  whenever password login itself is off.
* **Behavior change when it is on:** the endpoint now applies the same lockout
  as `/password/login/` (shared counter, keyed on the same identifier, `423`
  once the threshold is crossed) and the same TOTP step-up. A TOTP-enabled
  account therefore receives a `TOTPChallengeResponse`
  (`status=TOTP_REQUIRED`, `challenge_token`) with HTTP 200 instead of a token
  pair; finish it at `POST /totp/challenge/verify/`. A client that reads
  `access` unconditionally will fail loudly rather than silently skipping the
  second factor. `PASSWORD_LOGIN_STEP_UP=False` opts out of the step-up on
  both paths, as before.
* The route also moved out of the always-on `sessions` gate entry into its own
  `legacy_token` entry, so a host assembling its own URLconf from the
  factories gets no `/token/` route unless the setting is on. `/token/refresh/`
  and the `/sessions/` management endpoints are unaffected and stay always-on.
* `/token/` is deprecated: it is an alias of `POST /password/login/` kept for
  clients pinned to the token-pair response shape. New deployments should use
  the dedicated path and leave this setting alone.

**SSO: what the assertion does not say is no longer read as consent.** Four
`absent ⇒ accept` branches in `sso_service.py` now refuse, each with its own
named opt-out so a deployment flips only the one its IdP forces:

* an assertion with no `Conditions` (or a `Conditions` with no `NotOnOrAfter`)
  has no validity window and never expires — refused.
  **`STAPEL_AUTH['SAML_REQUIRE_CONDITIONS']`, default `True`.**
* an assertion with no `AudienceRestriction` is addressed to nobody in
  particular, so an assertion the IdP minted for a DIFFERENT service provider
  was accepted here — refused.
  **`STAPEL_AUTH['SAML_REQUIRE_AUDIENCE']`, default `True`.**
* a response with no `InResponseTo` answers no request of ours, so the
  single-use request-id correlation has nothing to bite on (IdP-initiated
  login CSRF) — refused. Deployments that really run IdP-initiated SSO (a tile
  in the IdP's app dashboard) must now say so:
  **`STAPEL_AUTH['SAML_ALLOW_IDP_INITIATED']`, default `False`.**
* an SSO login could take over an EXISTING local account purely because the
  email string matched — no `email_verified` is checked anywhere on the OIDC
  path, and an IdP is free to assert any address, including the deployment's
  own admin@. An existing account is now claimed only when the user already
  holds a membership in that org, or the address is inside the org's
  configured `domain` (a staff-only, org-unique field). Otherwise the login is
  refused (`?error=sso_invalid_response`) and the account is left alone.
  **`STAPEL_AUTH['SSO_LINK_EXISTING_BY_EMAIL']`, default `False`,** restores
  the old wholesale behavior. Just-in-time provisioning of a NEW account is
  unchanged. **Upgrade note:** set `Organization.domain` for every org whose
  members already have accounts here — the field used to be decorative for
  login and is now load-bearing.

**Permission allowlists are deny-by-default.** `PasswordViewSet` and
`QRAuthViewSet` resolved permissions from a list of AUTHENTICATED actions and
answered `AllowAny` for everything else, and `AdminUserViewSet` declared
`AllowAny` at class level with the staff/service-key check written inside
`create_user`'s body. No endpoint was actually open — every action that
existed was classified — but the cost of adding one was "public". The lists
are inverted now (they name the PUBLIC actions; anything unlisted needs a
session, plus `DenyEnrollOnly`), matching the shape `TOTPViewSet` and
`PasskeyViewSet` already had, and the admin broker carries the new
`stapel_auth.permissions.IsStaffOrServiceAPIKey` at class level. No setting:
there is no deployment for which "an action nobody classified is public" is
the right answer. The refusal body and status for `POST /admin-users/` are
unchanged (structured 403, not DRF's 401).

**Guest minting is capped.** `POST /anonymous/` is unauthenticated by design
(`AUTH_ANONYMOUS`, still on by default — a guest session carries no
privileges, and turning it off would silently break every guest flow in the
fleet) and every call created a real `User` row plus a JWT, with a
caller-supplied `device_id` as the only dedup: no captcha, no throttle, no
counter. **New setting `STAPEL_AUTH['ANONYMOUS_RATE_LIMIT_PER_HOUR']`,
default `20`** — new guests per client per hour, `429` beyond it, `0`
disables the cap. Reusing an existing guest session (same `device_id`, or
presenting the anonymous JWT) costs nothing, so the legitimate flow is
untouched; raise the number if your deployment fronts many guests behind one
NAT.

**`OTP_LENGTH` now defaults to `6`** (was `4` — a 10⁴ space that
`OTP_MAX_ATTEMPTS` and `OTP_RATE_LIMIT_PER_HOUR` narrow but do not enlarge).
Set `STAPEL_AUTH['OTP_LENGTH'] = 4` to keep short codes. `MOCK_OTP_CODE`
still defaults to `'0000'`; mock mode is a development affordance and its
length has never had to match.

**The hourly limits in `conf.py` are consumed rather than decorative.**
`OTP_RATE_LIMIT_PER_HOUR` (default `3`) and `MAGIC_LINK_RATE_LIMIT_PER_HOUR`
(default `3`) shipped as documented caps that no code read: OTP sends were
throttled only by `OTP_RESEND_COOLDOWN` (a gap between sends — 120 codes an
hour to one address at the default 30s), and `MagicLinkService` used a
hardcoded `RATE_LIMIT = 3` that ignored the setting. Both are wired now, per
identifier, `0` disables. **Upgrade note:** if you were relying on more than
three OTP sends per hour to one address, raise
`OTP_RATE_LIMIT_PER_HOUR` — the shipped value is now enforced.

### Security — the 2026-08-11 audit's authentication findings

**AUTH-01 — a wrong password was a password.** The legacy `POST /token/`
endpoint authenticates through `django.contrib.auth.authenticate()`, and the
deployment wired `stapel_core.django.jwt.session.EmailAuthBackend`, which
resolved a user by email and returned it without comparing a secret. The
backend is fixed in stapel-core; what lands here is the regression gate that
would have caught it — `tests/test_legacy_token_credentials.py` wires the real
backend stack (this suite's settings never did, which is why the deployed
configuration was the one nobody exercised) and asserts that every password
alias refuses a wrong nonempty password with no token, no cookie and no
session row, and that the stack passes core's `stapel_auth_backends` boot
check.

**AUTH-02 — a forged refresh token bought real tokens.** `POST
/token/refresh/` decoded the submitted token with `verify=False`, trusted its
`user_id`/`jti`, signed a fresh pair, and only then asked the session table
whether that was legitimate. Verification now comes first — signature,
algorithm, expiry, issuer, audience — followed by a token-type check (an
access token is signed by the same key and is not a refresh credential). A
token whose jti no `UserSession` tracks is refused instead of being read as a
pre-session-tracking legacy token, which is the state a forgery lands in;
`STAPEL_AUTH['ALLOW_UNTRACKED_REFRESH']` (default `False`) re-opens that door
for a deployment that needs it as a migration aid.

**AUTH-03 — a magic link walked past TOTP.** `magic_link/views.py` asked
`getattr(user, "totp_enabled", False)` — an attribute the user model does not
have, so the default answered "no second factor" for every TOTP user. It asks
`TOTPService.is_enabled(user)` now, and so does the second copy of the same
expression in `mfa/views.py`. `tests/test_user_attribute_probes.py` closes the
shape rather than the two instances: every string-literal attribute this
package probes on a user object must exist on the configured user model.

**AUTH-04 — password reset was an admission nobody admitted to.** Both reset
verify endpoints called the low-level mint directly, so a disabled account
walked in, a first-login obligation was skipped, and the session that came out
was untracked. Both go through `_issue_session_tokens` on the new
`SessionPath.PASSWORD_RESET`, as does the legacy `/token/` endpoint, which had
been running the admission predicate by hand and minting around the
choke-point.

**AUTH-05 — revocation that failed quietly, rotation that raced.** A failed
`SessionService.revoke_all` during a password change was logged and swallowed,
reporting a recovery that had not happened; it propagates now. Refresh
rotation reads its session row `select_for_update` inside the transaction that
writes it, and looks it up by `(jti, user)` so one user's jti cannot rotate
another's session. Changing a password with the current one revokes every
*other* session — the reaction to a suspected compromise no longer leaves the
attacker logged in — while sparing the session the request is made from.

### Notes

- `tests/test_contract.py::test_matches_monolith_auth_slice` is red again, and
  as in 0.14.6 it is not this library's emission that is wrong. Declaring the
  real permission on `AdminUserViewSet` changed what `PermissionAwareAutoSchema`
  renders into the description of `/auth/api/v1/admin-users/`: it no longer
  claims `**Permissions:** AllowAny` for an endpoint that was never actually
  open. `docs/schema.json` here was regenerated to match; the sibling
  `stapel-example-monolith` aggregate it is byte-compared against was not, so
  the stale half is the one still advertising the old string. Regenerating that
  aggregate closes it with a zero diff. Module CI is unaffected — the test is
  skipped when the monolith sibling is absent, which is every CI run — so this
  is a workspace-only gap, recorded here rather than left for someone to
  rediscover.

- `tests/test_error_i18n.py::test_error_reference_matches_a_fresh_regeneration`
  is red for a cross-repo reason worth stating exactly, because the shape
  invites misattribution. `docs/errors.{en,ru,es}.md` render every key in the
  registry of the harness instance, and that instance co-mounts stapel-gdpr;
  the gdpr security wave adds three keys (`error.403.gdpr.account_closed`,
  `error.410.gdpr.download_consumed`, `error.503.gdpr.closure_unavailable`),
  which is the 127 → 130 difference the byte comparison reports. Regenerating
  the reference here does not close it: the other seven `gdpr.*` strings are
  translated in the shared `stapel-translate` builtin corpus, these three are
  in no corpus at all, so a regeneration writes `_(en)_` fallback rows into the
  ru/es references and turns `test_error_docs_exist_for_every_language` red
  instead. The fix belongs where the strings do — the three texts join the
  builtin corpus (or stapel-gdpr starts shipping its own catalogs, as the
  ownership rule in stapel-core 0.22.0 would prefer) — after which
  regenerating here closes both. Neither `docs/errors.json` nor the contract
  triad is affected; those carry all 130 keys and `make contract-check` is
  clean.

## [0.20.2] — 2026-08-10

### Fixed — this module translates only the keys it owns

`translations/errors.{ru,es}.json` each carried 41 verbatim copies of the
cross-cutting keys stapel-core owns (`error.404.not_found`,
`error.400.field.*`, the verification and captcha keys, …). Not one was an
intentional reword — the coverage gate demanded them, because before
stapel-core 0.22.0 the canon it checked was the whole in-process registry.
Core ships those catalogs itself now and the loader merges them, so the copies
were a second, drifting shadow of a text this module does not answer for, and
the gate (`test_catalog_gate_green`) correctly went red on them. That red is
what blocked every tag in this repository.

ru 128 → 87 keys, es 127 → 86. What this module still answers for — every key
it owns, in every target language — is what
`test_every_language_covers_every_key_this_module_owns` now checks, scoped
through `owned_keys` / `owner_of_dir`.

The reference does not move: `docs/errors.{en,ru,es}.md` regenerated after the
deletion are **byte-identical** to the ones regenerated before it, because
stapel-core 0.23.1 resolves a key this module does not own from its owner's
catalog (`module_catalog`). Verified as bytes, not asserted as intent — and
`test_error_reference_matches_a_fresh_regeneration` now keeps it that way, so a
committed reference can never again be green while being unreproducible.

The `stapel-core` pin moves to `>=0.23.1` accordingly: with an older core these
pruned catalogs would resolve to English at runtime.


## [0.20.1] — 2026-08-09

### Added — Spanish ships as a language of the library, not as a host override

`translations/errors.es.json` (127 keys) + `docs/errors.es.md`, generated by the
same contour that produces Russian — no hand-written JSON, no product-side
override file. 111 values are lifted verbatim from the curated
`stapel-translate` builtin corpus (`origin: seed:stapel-builtin`), which is what
"clients don't spend tokens" means in practice: the corpus was paid for once.
The remaining 16 are machine translations of this module's own keys, recorded
`origin: llm` — **unreviewed**, and counted as such by the gate now that
stapel-core 0.20.1 stopped treating a curated corpus as human sign-off. Nobody
has read these; `translate_catalogs --approve` is the state transition that
changes that, and it has not been run.

Register and terminology follow the corpus rather than being invented per
module: informal *tú* address, *espacio de trabajo*, *llave de acceso*, *nombre
para mostrar*.

The harness in `tests/test_error_i18n.py` is now language-generic — a language
is a tag in `LANGUAGES` plus whatever the corpus does not carry, and the
catalog, the provenance sidecar, the reference page and the gate all follow.
Adding the next language is not a second copy of this work.

### Packaging

`translations/*.json` was already declared here (this module was the wave-1
pilot), so the Spanish catalog ships with the wheel as the Russian one does.
The four sibling modules that carried catalogs without declaring them are fixed
in their own releases.

## [0.19.1] — 2026-08-02

### Packaging / contract

- `docs/llms.txt` — the fifth contract artifact — is now emitted, drift-gated
  by `make contract`/`contract-check`, and badged in the README. stapel-auth's
  render (~7261 tokens) exceeds the generator's default 4000-token budget; the
  ceiling is deliberately raised to 8000 for this module rather than trimming
  intent/summary lines to fit.
- `docs/llms.txt` is now listed in `package-data` so it actually ships in the
  wheel (it was being emitted and gated but not packaged).
- Badge canon + Python 3.14 classifier added to `pyproject.toml`/README.

## [0.19.0] — 2026-08-02

### Регистрацию наконец можно закрыть, оставив вход (#86)

`AUTH_EMAIL_REGISTRATION`, `AUTH_PHONE_REGISTRATION`,
`AUTH_OAUTH_REGISTRATION`, `AUTH_SSO_REGISTRATION` существовали с самого
начала, публиковались наружу как `can_register` — и **выключить их было
нельзя**. Проверка стояла не там: на ручке запроса кода и через «и».

```python
# было, otp/views.py: email_request
if (not auth_settings.AUTH_EMAIL_LOGIN
        and not auth_settings.AUTH_EMAIL_REGISTRATION):
    return error_403_forbidden()
```

Отказ срабатывал, только когда канал выключен **целиком**. Ровно в той
конфигурации, ради которой флаг и заводился — вход открыт, регистрация
закрыта — ручка принимала любой адрес, слала код, а `email_verify` делал
безусловный `User.objects.create`. У телефона то же самое. OAuth и SSO
свои оси не читали вообще. Флаг был табличкой на двери, которую никто не
запирал.

- **Гейт переехал туда, где аккаунт создаётся.** Новый модуль
  `registration.py` — одно место, решающее, можно ли родить учётку;
  сквозь него проходят ВСЕ пути создания: OTP почта и телефон (и свежий
  аккаунт, и промоушен гостевой сессии), `_resolve_oauth_user` (обе
  ветки — и промоушен, и создание), JIT-провижининг SSO. Существующий
  пользователь входит ровно как раньше по всем путям: вход — это не
  регистрация, как и смена собственной почты авторизованным.
- **Двери хозяина не тронуты** — иначе развёртывание с выключенными
  осями осталось бы вообще без способа завести аккаунт:
  `auth.provision_user`, `POST /admin-users/` (сервисный ключ или staff),
  обмен login-гранта, выписанного доверенным эмитентом. Гостевая сессия
  (`POST /anonymous/`) — не аккаунт, у неё своя ось `AUTH_ANONYMOUS`;
  а вот её промоушен в настоящую учётку — регистрация, и он под гейтом.
- **`AUTH_REGISTRATION_CLOSED_BEHAVIOR`** — отказ только незнакомым
  адресам превращает OTP-ручки в **оракул существования аккаунта**:
  перебором выясняется, кто заведён в организации. Три честных поведения,
  и у каждого своя цена, поэтому это настройка, а не переписывание:
  `silent` (**умолчание**) — ответ незнакомцу и участнику побайтово
  одинаков, просто код незнакомцу не доставляется; запись, кулдаун и
  блокировка создаются как обычно, так что даже 429 не становится
  побочным каналом, а сохранённый код в мок-режиме перестаёт быть
  публичной «0000». Оракула нет; цена — человек с опечаткой в адресе
  ждёт письмо, которого не будет. `request` — 403
  `error.403.registration_closed` сразу на `*/request/`: самое понятное
  сообщение и полный перебор. `verify` — код уходит, отказ на
  подтверждении: перебор И письма незнакомцам, зато минимальная разница
  с поведением до #86. Неизвестное значение падает в закрытый конец
  (`silent`), а не в открытый.
- OAuth и SSO отказывают названно (403 / редирект
  `?error=registration_closed`): чтобы узнать «этот гугл-аккаунт здесь не
  заведён», надо уже владеть этим гугл-аккаунтом — перебирать нечего.
- Новый ключ ошибки `error.403.registration_closed` (+ ru-каталог), новая
  ось в `capabilities.json`.

Чтобы закрыть регистрацию на своём развёртывании: выставить нужные
`AUTH_*_REGISTRATION` в `False` и заводить людей через
`auth.provision_user`. Умолчания не изменились — оси по-прежнему `True`
(кроме пароля), поэтому обычное развёртывание не замечает релиза.

## [0.18.0] — 2026-07-30

### Добавлено — `auth.admin_reset_password`: сброс пароля по распоряжению админа (#110)

Админ организации должен уметь сбросить пароль участнику. Соблазн —
отдать это вызывающему сервису: разрешить пользователя, `set_password`,
сохранить. Такая версия неправильна четырьмя разными способами, и каждый
из них закрыт здесь, а не там:

- **Старые сессии переживают сброс.** Сброс, оставляющий живые сессии,
  ничего не восстанавливает: тот, кто уже внутри, там и остаётся.
  Функция снимает все сессии (`SessionService.revoke_all` — блэклист JTI
  + `user.session_revoked` на каждую) и возвращает их число.
- **Новый пароль остаётся постоянным.** Его теперь знает кто-то кроме
  владельца аккаунта, значит он обязан перестать работать при первом же
  использовании. `first_login_policies` по умолчанию
  `["password_change"]` — механика #90; с 0.15.0 это требование держат
  все 19 путей выдачи сессии, а не только форма пароля. Организация
  может добавить `mfa_enroll` или передать `[]` — и тогда это решение на
  протоколе, а не умолчание.
- **Никто не знает, кто это сделал.** Актор ложится в `AuthAuditLog`
  (`event_type=password_reset`, `metadata.via="admin_reset"`,
  `actor_id`, `reason`). «Кто сбросил этот пароль» обязано отвечаться из
  собственного журнала auth, а не только из событий вызывающего сервиса.
  `via` отличает административный сброс от самообслуживания — на модели
  это один и тот же тип события.
- **Суперпользователя сбрасывает админ организации.** Админ
  организации — роль внутри одного воркспейса; staff — роль над всем
  развёртыванием, и первая никогда не должна быть маршрутом во вторую.
  Граница держится здесь, потому что вызывающий сервис знает, кто
  администрирует воркспейс, и ничего не знает о том, кто администрирует
  развёртывание. Ответ — `error.403.privileged_account`.

Сгенерированный пароль возвращается РОВНО один раз, не логируется и не
едет ни в одном событии (канон приватности login-грантов). Неизвестный и
кривой `user_id` дают ОДИН И ТОТ ЖЕ `error.404.not_found` — вызывающий
строит свой анти-оракул поверх, и этот шов не должен подкладывать ему две
разные формы для утечки.

- Новый ключ ошибки `error.403.privileged_account` (+ ru-каталог).

## [0.17.0] — 2026-07-30

### Политики первого входа — набор независимых требований, а не выбор одного (#90)

`auth.provision_user` принимал одну строку `first_login_policy` и писал
создание аккаунта так:

```python
password_change_required=(policy == "password_change"),
mfa_enrollment_required=(policy == "mfa_enroll"),
```

— то есть запрос любого из требований **активно снимал** второе.
Организация не могла потребовать и смену пароля, и второй фактор. Не
потому, что механики не было: строка пользователя несёт два независимых
булева с волны 0, `required_intermediate` всегда разрешала их по порядку
(сначала смена пароля, потом enroll), а `POST /password/forced-change/`
всегда сцеплялся в mfa-интермедиат, когда подняты оба. Ограничение жило
целиком в этом payload — и именно из-за него галочки в модалке
приглашения были инертными.

И это перестало быть декоративным в 0.15.0: `first_login_error` стоит
внутри `_issue_session_tokens`, единственного минтера, через который
проходят все 19 путей выдачи полной сессии, а `FIRST_LOGIN_GATE_PATHS`
по умолчанию `'*'`. Поднятый флаг теперь закрывает вход везде, а не
только по паролю.

- **`first_login_policies`** (массив) в `auth.provision_user`.
  `password_change` и `mfa_enroll` компонуются; `[]` — осознанное «без
  требований». Устаревший `first_login_policy` (строка) читается, когда
  множественного ключа нет, как набор из одного элемента — потребитель,
  прибитый к stapel-workspaces < 0.13, продолжает работать. **Отсутствие
  обоих ключей — структурная 400, а не пустой набор**: опечатка в имени
  ключа не должна тихо создавать аккаунт вообще без требований.
- **`auth.apply_first_login_policies`** (`{user_id, policies[]}` →
  `{applied[]}`) — поднять политики на СУЩЕСТВУЮЩЕМ аккаунте. Канонический
  вызывающий: приём приглашения в stapel-workspaces, применяющий
  `provisioned_user_policies` организации. **Аддитивна, никогда не
  вычитает**: флаги живут на аккаунте, а вызывающие — на организации, и
  вычитающий контракт позволил бы одному тенанту опустить планку другого.
  Уже выставленная политика и `mfa_enroll` против аккаунта с сильным
  фактором пропускаются и не попадают в `applied`.
- **`FirstLoginPolicyService.POLICIES` / `POLICY_FLAGS` / `normalize_policies`
  / `flag_kwargs` / `apply`** — словарь политик и отображение
  «политика → колонка» в одном месте. `flag_kwargs` называет ВСЕ флаги, а
  не только поднимаемые: перечисление одних только True оставляет
  остальные на модельном дефолте — ровно так поведение «поднял один,
  снял другой» и переживает рефакторинг незамеченным.

### Известное ограничение (названо явно)

Флаги первого входа живут на пользователе, а не на членстве. Аккаунт,
вступивший в организацию А с `mfa_enroll`, закрыт для ЛЮБОГО входа,
включая вход в организацию Б, пока не зарегистрирует фактор. Это честное
прочтение предусловия на уровне учётных данных — и причина, по которой шов
дёргается только тогда, когда организация действительно настроила
политику.

## [0.16.0] — 2026-07-30

### Added — деактивация аккаунта наконец объявляется наружу (#92)

`is_active=False` был локальным фактом. С 0.15.0 гвард сессий отказывает
деактивированному аккаунту на всех 19 путях выдачи — и на этом всё
кончалось: вниз по потоку никто не узнавал о флипе, поэтому
деактивированный пользователь сохранял все членства в воркспейсах,
продолжал висеть в списках участников и продолжал стоить владельцу
оплаченное место. Деактивация не распространялась никуда, кроме входа.

- **`user.deactivated` / `user.reactivated`** (`events.py`,
  `schemas/emits/`) — новые события транзакционного аутбокса.
  `user.deactivated` = `{user_id, reason?, actor_id?}`,
  `user.reactivated` = `{user_id, actor_id?}`. Оба поля-опции реально
  опциональны: чекбокс в админке не несёт ни причины, ни актора.

- **`activation.py`** — сам шов. `deactivate_user(user, reason=None,
  actor=None)` и `reactivate_user(user, actor=None)` (оба экспортированы
  лениво из корня пакета) возвращают `True` только на настоящем переходе
  и открывают транзакцию, внутри которой эмит атомарен с записью.
  `is_deactivated(user)` делегирует в
  `sessions.guard.account_disabled_error` — тот же предикат, на который
  уже опираются пути выдачи, чтобы модуль и гвард не могли разъехаться в
  определении «отключён».

- **Эмитит наблюдатель, а не точка вызова.** `is_active` — обычное поле
  Django с чекбоксом в любой админке, поэтому событие вешает пара
  `pre_save`/`post_save` (подключается в `AppConfig.ready`), следящая за
  настоящим переходом значения. Сервисный вызов, галка в админке и
  `manage.py shell` объявляют одинаково и ровно один раз, а
  пересохранение уже деактивированного пользователя не объявляет ничего —
  идемпотентность в источнике, а не в потребителе. `pre_save` пропускает
  вставки, `loaddata` и записи, чей `update_fields` не может задеть
  `is_active`, поэтому лишнего SELECT на горячем пути логина
  (`update_last_login`) не появляется.

### Важно для потребителей: это НЕ переименование `user.deleted`

Три состояния разведены намеренно и не должны писаться одинаково:

| Состояние | Механизм | Обратимо | Событие |
|---|---|---|---|
| `active` | `is_active=True` | — | — |
| `suspended` | `is_active=False` — административное снятие доступа | **да**, ничего не разрушено | `user.deactivated` |
| `deleted` | GDPR-стирание (`gdpr.AuthGDPRProvider.delete`) — строки удаляются | нет | `user.deleted` (модуль gdpr) |

Потребитель `user.deactivated` обязан **приостанавливать, а не удалять**,
и обязан снимать приостановку на `user.reactivated`. Зеркальное событие
не декоративное: без него деактивация — дверь в одну сторону, и
восстановленный аккаунт входит в пустой продукт.

### Известные слепые зоны (задокументированы, не заметены)

- `QuerySet.update()` и `bulk_update` минуют сигналы модели: массовый
  `User.objects.filter(...).update(is_active=False)` деактивирует молча.
  Для этого и существует `deactivate_user()`.
- Голый флип поля (`user.is_active = False; user.save()`) не несёт
  `reason`/`actor` — событие уйдёт без них.
- `post_save` срабатывает вне транзакции, которую `Model.save()` открывает
  сам себе, поэтому эмит атомарен с записью только когда транзакцию держит
  вызывающий. Сервисные функции её открывают, change-form админки уже
  работает внутри транзакции; голый `save()` в шелле эмитит в autocommit.

## [0.15.0] — 2026-07-30

### Security
- **One place decides whether an account may be handed a session.** The
  library could mark a user `is_active=False` and could hang first-login
  policies on them (`password_change_required` / `mfa_enrollment_required`),
  but only the password login path ever looked. Every other path that mints a
  session — email/phone OTP, OAuth (both the token exchange and the browser
  callback), magic link, QR session-share, passkey sign-in, login-grant, SSO,
  the instant authenticator-change paths — minted one without a glance. So a
  **deactivated account signed in through OTP**, and a **forced password
  change or 2FA enrollment was walked around with a magic link**. Not two
  bugs: one invariant that was held by the politeness of its callers.

  The invariant now lives in `sessions/guard.py` and is enforced inside
  `sessions.views._issue_session_tokens`, the final minter every full-session
  path funnels through. Deliberately **not** inside `create_tokens_for_user`:
  that primitive is shared with the *intermediate* paths (forced change, the
  enroll-only exchange, password reset), which must stay outside the
  invariant — gating them would lock a user out of the very step they are
  being held on.

  - `is_active=False` → refused on every path, unconditionally, with no
    configuration knob. The refusal carries no account detail, so it cannot be
    used to probe which accounts exist.
  - a first-login flag → refused **with a next step**: the denial carries a
    freshly minted `challenge_token` and a `requires` label, so a flagged user
    who arrived by magic link is pointed at `POST /password/forced-change/`
    (which never asks for the password they do not know) instead of hitting a
    dead 403.

- **SSO was minting sessions around the gate.** `SsoService.
  issue_session_and_redirect` carried a verbatim copy of the minter's body —
  token pair, `UserSession` row, audit event, login notification — and so
  reproduced both holes word for word. It also never checked `is_active` for
  an *existing* user: `get_or_create(email=..., defaults={'is_active': True})`
  applies the default only on create, so a deactivated account came back
  through the ACS and got a live session. The duplicate is gone — SSO calls
  the shared minter (one session row, still the `sso_login` audit verb via the
  new `audit_event` argument) and inherits the gate.

### Added
- `STAPEL_AUTH['FIRST_LOGIN_GATE_PATHS']` (default `'*'`) — which issuance
  paths the first-login **flags** block. `'*'` reads a flag as "a mandatory
  step before ANY admission"; a list of `sessions.guard.SessionPath` labels
  narrows it (`['password', 'legacy_token']` is the "password admission only"
  reading, which deliberately leaves OTP/magic-link/OAuth open to a flagged
  account). `no_env`. Does **not** cover `is_active`, which is never
  negotiable.
- `sessions/guard.py`: `session_precondition_error(user, *, path)` and its two
  halves `account_disabled_error` / `first_login_error`; the typed
  `SessionIssuanceDenied` (a `StapelServiceError`, so the stapel-core DRF
  handler renders it identically on every JSON path with no per-caller
  `try/except`); `SessionPath` labels for all 19 issuance paths;
  `denial_redirect_url` for the browser-redirect paths.
- Browser-redirect paths (magic link, OAuth callback, QR session-share, SSO
  ACS) map a denial to `{FRONTEND_URL}/login?first_login=<requires>&
  challenge_token=<tok>&next=<n>` — the shape the TOTP-challenge redirect
  already used, plus a discriminator — rather than to a JSON body the user
  would stare at in the address bar.
- `tests/test_session_issuance_gate.py`: the table walks `SessionPath.ALL`
  rather than a hand-kept list, and two AST tests enumerate *callers* — every
  `_issue_session_tokens` call must declare a path label, and every
  `create_tokens_for_user` caller must be inside the minter or on an explicit
  reason-annotated bypass roster. A hand-maintained list of "which paths are
  final" is precisely what went stale and let SSO through; the build fails now
  instead of a comment going out of date.

### Changed
- The duplicated checks are gone: the legacy `/token/` endpoint
  (`sessions/views.py`) and `password/login` (`password/views.py`) read the
  same predicate the minter uses instead of re-implementing it.
  `first_login_intermediate_response` is now the *interactive rendering* of
  that one rule (a 200 challenge DTO where the minter raises), not a second
  copy of it. Password-login response shapes are unchanged.
- The legacy `/token/` first-login 403 now carries `requires` /
  `challenge_token` / `expires_in` in `params`, so that endpoint stops being a
  dead end too. Error keys and status codes are unchanged.

### Compatibility
- Active accounts with no first-login flags — that is, everyone outside org
  provisioning — are unaffected on every path.
- Minor, not patch: a deployment that had been relying (knowingly or not) on a
  deactivated or flagged account still being able to sign in via OTP, magic
  link, OAuth, QR, passkey, login-grant or SSO will see those paths start
  refusing. That is the fix.

## [0.14.6] — 2026-07-30

### Fixed
- **Passkeys were unusable on any deployment that only set `FRONTEND_URL`.**
  `conf.py` has documented `WEBAUTHN_RP_ID: None  # Falls back to request host`
  since the port, but `PasskeyService._rp_config()` fell back to the literal
  string `'localhost'`. The `origin` in the very same tuple already derived
  from `FRONTEND_URL`, so the ceremony went out with `rpId='localhost'` next to
  `origin='https://<the real host>'`. WebAuthn requires the rpId to be the
  origin's host or a registrable suffix of it, so browsers abort with a
  `SecurityError` and no passkey can be registered or used at all. The rpId now
  falls back to the `FRONTEND_URL` host, from the same source as the origin;
  `'localhost'` survives only for the case where `FRONTEND_URL` is unset
  itself, and an explicit `WEBAUTHN_RP_ID` still wins (that is how you share
  one credential across subdomains: `rp_id='example.com'` for an origin of
  `https://app.example.com`). Found on a live deployment by meettoday.

  Compatible: where `FRONTEND_URL` is unset or is itself a localhost URL, the
  resolved rpId does not change.

### Notes
- `tests/test_contract.py::test_matches_monolith_auth_slice`, red since 0.14.3
  and released around twice, is **green again** — and it was never this
  library's fault. The library's own emission was correct; the sibling monolith
  aggregate it is compared against had simply not been regenerated since
  2026-07-17, so it was missing the six endpoints added by 0.9.0 / 0.11.0 /
  0.12.0. Regenerating that aggregate closes the gap with a zero diff against
  the committed `docs/schema.json` — no contract change was needed here.

## [0.14.5] — 2026-07-29

### Fixed
- **`OTP_MAX_ATTEMPTS` did nothing.** It has shipped in `conf.py` since day one
  and was read by nobody: the verify path hardcoded `attempts >= 5`, the log
  said `/5` and the response said `5 - attempts`. A host that raised the limit
  still got five tries and had no way to find out. Both verification services
  now read it — and read it lazily, at call time, like everything else in this
  package, so a long-lived service instance cannot freeze whatever the settings
  said when it was constructed.
- **The lockout was a literal `timedelta(minutes=10)`** next to that setting.
  It is now `OTP_BLOCK_DURATION` (default 600 s), and the `retry_after` the API
  returns comes from the same value instead of a separate hardcoded `600`.

### Notes
- Worth knowing when tuning these: the **send** path refuses a new code while
  the latest verification for that address is blocked. So the block does not
  only stop guessing — it also stops asking for a fresh code, for the same
  duration. Five wrong codes therefore cost a full `OTP_BLOCK_DURATION` before
  anything can be retried at all, which is what "very few retries" feels like
  from the outside. Nothing here is remembered beyond that window.


## [0.14.4] — 2026-07-28

### Fixed
- **OTP codes always went out in English.** `EmailVerificationService` and
  `PhoneVerificationService.send_verification_code()` called
  `request_notification()` without `language`, although the parameter exists in
  `stapel_core.notifications` for exactly this. An anonymous OTP request has no
  `user_id` and no profile yet, so the resolver in `process_notification` had
  nothing to look the language up from and fell back to a hardcoded `"en"` —
  while Django had already resolved the request's language via
  `LocaleMiddleware`. Both services now pass `language=get_language()`.
  Found on a live deployment by meettoday, 2026-07-28.

### Known
- `tests/test_contract.py::test_matches_monolith_auth_slice` is red and was
  already red on a clean tree before this change (verified by stashing it) —
  the contract has drifted from the monolith slice for an unrelated reason.
  Released anyway by explicit decision; tracked separately.


## [0.14.3] — 2026-07-26

### Added — `error-keys/` is finally mounted

`AuthErrorKeysView` has existed since the port but no `urls*.py` ever mounted it — in
*any* stapel library. stapel-translate's `error_collector` polls
`/{prefix}/api/v1/error-keys/` on every service, so the whole endpoint class
answered 404 from Django's URL resolver and the collector harvested nothing
while reporting a plain `HTTP 404`. It is now mounted in `urls_v1.py` at
`error-keys/` (v1 canon), service/staff-gated as the base view declares.

Deliberately **not** in the contract triad: `ErrorKeysView` sets
`schema = None` and `/error-keys` is on the flows allowlist, so `make
contract` is a no-op diff — this is infrastructure, not product surface.

### Fixed — the OIDC discovery document advertised URLs that do not exist

`/.well-known/openid-configuration` handed external clients four literals
carried over from the pre-library monolith (which mounted these views directly
under `{URL_PREFIX}`): `…/api/v1/auth/token/`, `…/auth/token/refresh/`,
`…/auth/me/` — a duplicated `auth/` segment — and `/{URL_PREFIX}.well-known/
jwks.json`, which matched neither the DRF route nor the nginx static file.
Every client that read discovery walked into a 404 on the most expensive
surface there is: a published contract with parties we do not control.

The endpoints are now derived with `reverse()`, so they follow the host mount
and the `v1/` segment and cannot drift again; a route a deployment left
unmounted (feature-gated factories) is omitted instead of advertised. New
`STAPEL_AUTH['JWKS_URI']` makes the second legitimate JWKS home — the static
`jwks.json` that `generate_jwks_to_dir()` writes for nginx at the host root —
an explicit deployment claim rather than a silent guess.

Why nothing caught it: `tests/conftest.py` pointed `ROOT_URLCONF` at the inner
`stapel_auth.urls_v1`, so the suite never crossed the mount (the stapel-
workspaces pre-v1 incident, one repo over). The suite now runs on
`tests/conftest_urls.py` (`auth/api/` + `urls.py`), and
`tests/test_openid_discovery_contract.py` puts every URL discovery emits back
through `resolve()`. Side effect of the same fix: the committed SA flow docs
under `docs/flows/` were generated from that bare urlconf and published
un-mounted paths (`POST /password/login/`) — regenerated, and they now agree
with the canonical `docs/flows.json` byte for byte.

## [0.14.2] — 2026-07-26

### Added
- **`stapel_auth.E004` — mock OTP on a host that is not local.** E001 ties
  that hazard to `DEBUG=False`, which is exactly what a stand on dev
  settings never trips: the ironmemo stand served a fixed OTP code for ANY
  address, on the public internet, months after real email/SMS providers
  were wired — "sign in as anyone", with nothing in the system objecting
  (found 2026-07-26). E004 keys off REACHABILITY instead: mock OTP plus an
  `ALLOWED_HOSTS` entry that is not localhost-ish (`*` counts as public).
  A deployment that runs on a pin code on purpose silences it explicitly
  via `SILENCED_SYSTEM_CHECKS` — the intent then lives in that settings
  layer instead of being inherited from a DEBUG flag.

## [0.14.1] — 2026-07-26

### Added
- **`OAUTH_CALLBACK_PATH`** — the path this service sends as `redirect_uri`
  is now a setting (default: the current `/{url_prefix}api/v1/oauth/
  {provider}/callback`). That value is registered verbatim in Google's /
  GitHub's / Zoom's console, i.e. it is a contract with a third party that
  no deployment can update from code — and moving the module's urlconf onto
  `/v1/` silently re-pointed it, so every live OAuth app started failing
  with `Error 400: redirect_uri_mismatch` and nothing in our logs (ironmemo
  stand, 2026-07-25). A deployment that cannot re-register right away pins
  the old path here; a future canon change cannot invalidate it again.

## [0.14.0] — 2026-07-25

### Added — system check `stapel_auth.E003`: `FRONTEND_URL` unset with `DEBUG=False`

Every redirect this pair issues off session (SSO callback, magic link, QR
account-conflict, OTP-challenge continuation, security email/phone
verification links) falls back to `auth_settings.FRONTEND_URL or ""` with no
further validation. Missing it used to be a plain `warnings.warn` in
`apps.py` — easy to miss (Python warnings routinely never reach a
container's visible log stream), and a host's own legacy flat `FRONTEND_URL`
Django setting carrying a dev-friendly default (e.g. `http://localhost:3000`)
commonly satisfies `AppSettings`' resolution order anyway, so real users' auth
redirects silently land on a developer's laptop instead of the deployment's
real origin. `manage.py check`/`migrate` (which most deploy entrypoints run
before serving) now fails loudly instead, same treatment as `stapel_auth.E001`
(mock OTP) and `E002` (OTP length).

### Removed
- The `warnings.warn` in `AppConfig.ready()` for unset `FRONTEND_URL` — superseded by `E003`.

## [0.13.0] — 2026-07-24

### Changed — OTP length: storage cap 8, generated length configurable
- `otp.constants.OTP_CODE_LENGTH` is now the STORAGE/WIRE CAP (4 → 8;
  migration 0018 widens EmailVerification/PhoneVerification.code).
- Generated code length is the new runtime setting
  `STAPEL_AUTH["OTP_LENGTH"]` (default 4 — behavior unchanged);
  `MOCK_OTP_CODE` may now be 4-8 digits (e.g. a 6-digit sandbox pin).
- `capabilities()` otp meta exposes the GENERATED length, not the cap.
- New system check `stapel_auth.E002`: OTP_LENGTH/MOCK_OTP_CODE over the
  cap fail loudly at boot (silent wire truncation is impossible).

## [0.12.1] — 2026-07-24

### Fixed
- **0.12.0/0.11.0 wheels shipped without `stapel_auth.login_grant`** — the
  explicit packages list didn't include the new package, so importing
  `stapel_auth.urls_v1` from the wheel raised ModuleNotFoundError. List
  extended; wheel contents verified before tagging this time.

## [0.12.0]

Auth side of the org-program security hardening (workspaces-org-program §C,
Wave 3). Requires stapel-core ≥0.14 (factor `strength`, the
`password_change_required`/`mfa_enrollment_required` user flags, the
`login` auth_type, the namespace-tolerant username validator).

### Org provisioning (§C1)
- New comm function `auth.provision_user` `{username, password?, email?,
  display_name?, first_login_policy}` → `{user_id, generated_password?}`
  (schema committed in `schemas/functions/auth.provision_user.json`).
  Creates an org-provisioned `auth_type="login"` account with the FULL
  namespaced username `org_slug/local` (exactly one `/`; validated by the
  new `utils.parse_namespaced_login` / `utils.validate_local_username`
  helpers on top of the core username canon) and no email anchor by
  default. Caller-provided passwords are validated by the deployment's
  password canon; an omitted password is generated crypto-strong
  server-side and returned exactly ONCE — it is never logged and never
  rides an event payload (tested). Structured failures instead of raises:
  `{"error": "error.400.username_namespace_invalid" | "error.409.username_taken"
  | "error.400.bad_request"}`. Emits `user.registered` with an additive
  nullable `display_name` hint (schema updated) for downstream consumers.
- New comm function `auth.mfa_status` `{user_id}` → `{has_strong_mfa,
  factors: [{id, strength}]}` (schema in
  `schemas/functions/auth.mfa_status.json`) — the factors the user can
  actually complete, with the strength canon applied; unknown users get
  `{false, []}`.

### Strength canon (§C2 — «email-код ≠ 2ФА»)
- The registered verification factors now declare `strength`: `totp`,
  `passkey` and `otp_phone` are **strong**; `otp_email` stays weak. Strict
  "has 2FA" checks everywhere go through
  `stapel_core.verification.strong_factors`.

### First-login intermediates (§C2)
- While `password_change_required`/`mfa_enrollment_required` is up, a
  successful password login returns `FIRST_LOGIN_REQUIRED {requires:
  "password_change"|"mfa_enroll", challenge_token, expires_in}` (cache
  token, 10-minute TTL — `FirstLoginPolicyService`) instead of a session;
  the same check runs in the TOTP step-up verify, so a TOTP-enabled flagged
  account still proves the second factor first. The `LoginResponse` union
  gains the third member. Flag-less logins are byte-identical to 0.11
  (release gate, tested).
- New endpoint `POST /password/forced-change/` `{challenge_token,
  new_password}`: password canon validation (a rejected password does NOT
  consume the challenge), clears the flag, mints a full session — or chains
  into the `mfa_enroll` intermediate when both flags are set.
- New endpoint `POST /mfa/enroll/exchange/` `{challenge_token}`: trades the
  challenge for a LIMITED enroll-only session — an access token with the
  `enroll_only` JWT claim, deliberately **no refresh token** (a refresh
  would mint a claim-free token and escalate silently) and no UserSession
  row. New DRF permission `DenyEnrollOnly` rides every authenticated view
  and cuts the surface down to TOTP setup/confirm, passkey registration and
  logout (central allowlist in `permissions.py`; structured 403
  `error.403.mfa_enrollment_required` elsewhere). Activating a strong
  factor clears the flag and the confirm response additionally carries the
  full-session `tokens` pair (TOTP confirm + passkey register complete).
- The legacy `POST /token/` obtain endpoint 403s flagged accounts with
  `error.403.password_change_required` / `error.403.mfa_enrollment_required`
  instead of silently bypassing the policy.
- Gating decision (documented in `urls_v1.py`): NO new conf flags — the
  intermediates are driven by USER flags and are byte-inert without them.
  `/password/forced-change/` rides the password factory's gate (it is only
  ever entered from a password login); `/mfa/enroll/exchange/` is a new
  `mfa.enroll` gate block mounted while EITHER `AUTH_TOTP` or
  `AUTH_PASSKEY_LOGIN` is on.

### MFA events (§C3)
- New outbox events `user.mfa_enabled` / `user.mfa_disabled` `{user_id,
  factor}` (schemas in `schemas/emits/`). ACCOUNT-LEVEL transitions of the
  "has a strong second factor" predicate, not per-factor ticks — a second
  passkey, or a TOTP disable while a verified phone still counts as strong,
  emits nothing, so the workspaces require_mfa consumer can
  suspend/unsuspend on the events directly. Emission points (atomic with
  the factor write): `TOTPService.confirm`, `TOTPService.disable`,
  `TOTPService.force_disable` (which also covers the delayed-change execute
  task) and `PasskeyService.registration_complete` / the new
  `PasskeyService.deactivate` (the passkey delete view now goes through
  it).

### Errors
- New keys + ru: `error.403.password_change_required`,
  `error.403.mfa_enrollment_required`, `error.400.username_namespace_invalid`,
  `error.400.first_login_challenge_invalid`.

### Docs/contract
- `docs/{schema,flows,errors,capabilities}.json`, the flow doc trees and
  the error/flow i18n catalogs regenerated; new `auth.first_login` flow
  documents the whole first-login machine.

## [0.11.0]

Login grant primitive (workspaces-org-program §B3, Wave 2) — the magic-link
mechanic generalized for service-to-service use. New `login_grant/` package:
a cache-stored, single-use, 15-minute token minted **by comm** instead of by
email — `auth.issue_login_grant` `{email, verified_email?, create_if_missing?,
language?}` → `{grant_token}` (registered in `apps.ready()`, committed schema
in `schemas/functions/auth.issue_login_grant.json`). The holder exchanges it
at `POST /grant/exchange/` for a full JWT session (same session mint, cookies
and audit as every other login flow; `AuthResponse` with
`LOGGED_IN`/`REGISTERED`). A grant minted with `create_if_missing` provisions
the account on exchange when the email is unregistered: `auth_type="email"`,
`is_email_verified` per the issuer's `verified_email` assertion (default
true), unusable password, `user.registered` emitted. The event payload (and
`schemas/emits/user.registered.json`) gains an additive nullable `language`
field — a dead-reckoning hint like `avatar_url` for downstream consumers
(profiles `app_language`); only login-grant provisioning populates it today.
New gate `AUTH_LOGIN_GRANT` (default **off**): gates the
`get_login_grant_urls()` factory (404 on host-assembled URLconfs) and the
view per-request (403 on the always-on `include('stapel_auth.urls')` mount),
surfaced as an `auth.login` capability axis. New error key
`error.400.grant_invalid` (expired/consumed/unknown grant) with ru
translation. Canonical caller: the workspaces invitation claim flow — the
invite email already proved mailbox ownership, so clicking the link can mean
"the account is ready" without a second email.

## [0.10.0] — 2026-07-20

Configurable password-as-identity policy (`AUTH_PASSWORD_DEANONYMIZES`, THE
IDENTITY MODEL knob). By default a password stays a CREDENTIAL, not an
identity: setting one on an anonymous guest session only makes that same
account portable (loginable from another device) and `register()` returns
`MODIFIED` — the row stays anonymous; only a verified anchor (email/phone/
social) deanonymizes. A deployment that deliberately wants classic
login/password accounts ("90s-style" — username+password IS the account)
sets `AUTH_PASSWORD_DEANONYMIZES=True`, and a password-only `register()` on
an anonymous session then promotes it (`auth_type="password"`, `REGISTERED`).
Off by default. Exposed as an `auth.registration` capability axis. Pair it
with the frontend's `registrationAnchors` including `"password"` so the
register surface actually offers the form (@stapel/auth-react ≥0.8.0).

## [0.9.0] — 2026-07-20

TOTP anti-takeover hardening — brings TOTP up to the same standard the
phone/email authenticator change flow already had. Previously TOTP only had
instant enroll (`setup`→`confirm_setup`) and instant disable: no atomic
replace, no delayed/cancellable mode for a lost device, and no notification
on change — a stolen session (or a leaked code/backup code) could strip 2FA
instantly with the owner never told. Closes that gap by reusing the
`AuthenticatorChangeRequest` model/status machine and the delayed-change
Celery tasks (`send_change_notifications` / `execute_pending_changes` /
`cleanup_expired_requests`) that already back phone/email changes, adding
`change_type="totp"` rather than a parallel model.

### Security fix
- `mfa.services.TOTPService.setup()` now requires proof of the CURRENT
  device (`code` or `backup_code`) when one is already active. Previously
  `setup()` unconditionally deactivated any existing active device with
  **zero proof** — an authenticated session (stolen or otherwise) could
  silently strip working 2FA by calling `/totp/setup/` then
  `/totp/setup/confirm/` with a code it computed itself, bypassing
  `disable()`'s proof requirement entirely. First-time enrollment (no
  active device yet) is unaffected — no proof required. Callers without
  the old device's code/backup code use the new delayed flow below instead.

### Added
- **Instant replace**: `POST /totp/setup/` now accepts optional `code` /
  `backup_code` in the body — proof of the current device, gating the
  re-enrollment that `POST /totp/setup/confirm/` completes as before.
- **Delayed (anti-takeover) mode for a lost device** — `change_type="totp"`
  on `AuthenticatorChangeRequest` (see `models.py` docstring for the
  encoding: `old_value` unused, `new_value` an opaque per-request marker
  since TOTP has no "new address" to reserve, unlike phone/email):
  - `otp.services.AuthenticatorChangeService.initiate_delayed_totp(user, ...)`
    — schedules a TOTP disable `DELAYED_PERIOD_DAYS` (14) out. Requires a
    verified email or phone (the notify/cancel channel); returns
    `{'error': 'no_verified_contact'}` cleanly otherwise — a lost device
    AND no recovery contact is a support case, not a silent path.
  - `POST /totp/change/delayed/initiate/`, `GET /totp/change/delayed/status/`,
    `POST /totp/change/delayed/cancel/` — same shape as the phone/email
    delayed endpoints, reusing their DTOs/serializers (`DelayedInitiateResponse`
    / `DelayedStatusResponse` / `DelayedCancelResponse` /
    `DelayedChangeCancelSerializer`).
  - Once the cooldown elapses, `tasks.execute_pending_changes` (already
    polled by the existing `BEAT_SCHEDULE`, no new beat entry needed) force-
    disables the device instead of swapping a contact field; the user
    re-enrolls afterward via the normal instant `setup`/`confirm_setup`
    pair. `tasks.send_change_notifications` sends the same day-1/7/13
    notifications, resolved to the user's current verified contact
    (`tasks._notify_kwargs_for_request`) since TOTP has no "old address" —
    `get_pending_status`/`send_change_notifications` display it as
    `"authenticator app"` rather than a masked address.
- **Notify on every TOTP change** (item 3): `mfa.services.notify_totp_change`
  — best-effort notification to the verified contact, wired into
  `confirm_setup` (`totp_enabled`), `disable` (`totp_disabled`, all three
  proof methods), and the delayed flow's day-1/7/13 + completion
  notifications above.
- New error keys `error.400.totp_proof_required` (setup called without
  proof while a device is active) and `error.400.totp_not_enabled`
  (delayed-mode initiate with no active device).
- Migration `0017_alter_authenticatorchangerequest_change_type` — adds the
  `totp` choice (additive, no data migration).

### Frontend follow-up (separate track)
- `POST /totp/setup/` needs `code`/`backup_code` fields wired for the
  "replace" case (only when TOTP is already enabled) — 400
  `totp_proof_required` if omitted.
- New delayed-mode screen: initiate (no body beyond optional `device_id`)
  → show `scheduled_at`/cancel affordance for 14 days → poll
  `/totp/change/delayed/status/` → cancel via
  `/totp/change/delayed/cancel/` with `change_request_id`. On
  `no_verified_contact`, surface a "contact support" dead-end rather than
  a retry.

## [0.8.0] — 2026-07-20

THE IDENTITY MODEL, enforced end to end: an account is REGISTERED
(`is_anonymous=False`) iff it has a verified identity ANCHOR (email, phone,
or a federated identity — OAuth/SSO). Credentials (password/passkey/TOTP)
never promote on their own — an anonymous user who sets a password stays
anonymous; the password only makes that SAME guest account portable
(loginable from another device).

### Added
- `otp.services.promote_anonymous_session(user, *, auth_type)` — the
  primitive that flips `is_anonymous`/`auth_type` and upgrades the
  `anon_*` placeholder username, factored out of the two inline branches
  that used to hand-roll it (`otp/views.py` `email_verify`/`phone_verify`).
  Now also called from the password module's OTP-verify-contact path
  (defensive — the precondition there normally makes an anon+verified state
  unreachable), OAuth login/callback, and SSO JIT provisioning.
- `AuthMethodInfo.can_login`/`.can_register` on every entry of
  `GET /auth/api/v1/capabilities/`'s `methods[]` — per-method capability,
  derived from the existing `AUTH_<M>_LOGIN`/`AUTH_<M>_REGISTRATION` settings
  pairs (kept for back-compat). `can_register` is always `false` for
  passkey/qr/magic_link — no registration axis exists for them.
- `"sso"` added to `AbstractStapelUser.AUTH_TYPE_CHOICES` (stapel-core
  0.12.5) — SSO-promoted accounts now get an accurate `auth_type` instead of
  being mislabeled.

### Fixed
- **Orphaning**: `password/views.py` `register()`, OAuth login/callback
  (`otp/views.py` `_resolve_oauth_user`), and SSO JIT provisioning
  (`sso_service.py` `SSOUserService.get_or_create_user`) used to silently
  create a brand-new account when called on an already-anonymous session,
  abandoning the guest row. All three now attach a FRESH anchor to the SAME
  anonymous row (promoting it) instead — a collision with a DIFFERENT
  existing account still resolves exactly as it did before (a genuine
  account-merge flow is a follow-up, not built here).
- **Response contract**: `password/change/otp/verify/` used to always
  return the contentless `SimpleStatusResponse`, even in the (normally
  unreachable, now defended) case where it promoted an anonymous session —
  a client's `session.adopt()` never fires without a `user`. It now returns
  a `PasswordOtpChangeResponse` (`AuthResponse | SimpleStatusResponse`):
  a full `AuthResponse` with fresh tokens when promotion happened, the
  original bare status otherwise.
- **Password registration on an existing anon session**: `register()` used
  to always create a new account, even when called with only a `password`
  and no email/phone (no anchor) — now correctly leaves the guest account
  anonymous (portable, not promoted) per THE IDENTITY MODEL, while still
  reusing the same row rather than orphaning it.

## [0.7.7] — 2026-07-20

Closes a deployment trap in the delayed (14-day, no-old-channel-proof)
authenticator-change strategy: `tasks.py`'s `send_change_notifications`,
`execute_pending_changes` and `cleanup_expired_requests` had no documented
Celery beat schedule anywhere — a host that installs this app and wires
`include('stapel_auth.urls')` gets working delayed-change *endpoints* but a
`PENDING` request just sits there forever unless the host happens to already
run these three tasks on some schedule of its own devising.

### Added
- `stapel_auth.BEAT_SCHEDULE` (also `stapel_auth.tasks.BEAT_SCHEDULE`) — a
  `CELERY_BEAT_SCHEDULE`-shaped dict naming the three tasks with concrete
  intervals (`execute_pending_changes` every 5 min, `send_change_notifications`
  hourly, `cleanup_expired_requests` daily), namespaced entry keys
  (`stapel-auth-*`) so merging into a host's own schedule can't collide with
  an unrelated task of the same short name. Discoverable, not auto-wired —
  installing this app still never touches a host's `celery.py`; see
  MODULE.md's new "Celery beat schedule" section for the exact merge snippet
  and the reasoning behind each interval.

## [0.7.6] — 2026-07-19

Consumer-facing fix (real report, meettoday migrators): a `session_share` QR
scan (`QRAuthViewSet.scan`) — and every other redirect-based login (magic-link
verify, SSO SAML/OIDC callback, OAuth social callback) — mints fresh httponly
JWT cookies via a plain HTTP redirect, entirely outside the SPA's own login
call. A bearer-mode `@stapel/auth-react` host had no way to tell "a redirect
just minted a live session for me" from "there was never a session" without
attempting a network refresh on every cold load — so it silently never
attempted one, and users landed on those flows looked logged out despite a
valid server-side session.

### Added
- `stapel_auth_hint` — a non-httponly, non-sensitive (`"1"`) companion cookie
  now set alongside the refresh-token cookie by every flow that mints one
  (`stapel_auth/hint_cookie.py`): QR `session_share` scan, magic-link verify,
  SSO SAML/OIDC callback, OAuth social callback, and the direct JSON-response
  login/refresh endpoints (harmless, for consistency). Same
  lifetime/Secure/SameSite/domain/path as the refresh cookie it accompanies;
  cleared alongside it on logout. `@stapel/auth-react ^0.5.3`'s
  `bootstrapProbe: "auto"` reads this cookie via `document.cookie` to decide
  whether a bearer-mode cold load is worth a refresh-probe, closing the QR
  session-share/magic-link/SSO/OAuth blind spot without paying a network
  round trip on visitors who were never on a cookie-issuing backend.

## [0.7.5] — 2026-07-17

Fixed an inverted-logic bug in `AuthCapabilitiesService.get_capabilities()`
(owner-caught in a live review): `phone_real = not USE_MOCK_SMS_OTP` /
`email_real = not USE_MOCK_EMAIL_OTP` treated a mock OTP provider as a
*disabled* channel. A mock provider does not disable delivery — it changes
delivery (the code goes to logs instead of a real SMS/email), which is the
whole point of the dev-canon default (`.env.local` ships mocks on so login
tabs stay usable without real providers wired up). The bug did the opposite:
it hid the email/phone login tabs exactly when mock was on.

### Fixed
- `email`/`phone` in `RegistrationCapabilities`/`LoginCapabilities` and the
  corresponding entries in `methods[]` are now gated **only** by the
  matching `AUTH_*_LOGIN`/`AUTH_*_REGISTRATION` axis — a mock OTP provider
  no longer disables the channel.

### Added
- `RegistrationCapabilities.email_mock` / `.phone_mock` and
  `LoginCapabilities.email_mock` / `.phone_mock` — additive transparency
  fields reporting whether that channel's OTP delivery is currently mocked
  (`USE_MOCK_EMAIL_OTP`/`USE_MOCK_SMS_OTP`), independent of `enabled`, so a
  host frontend can show a "dev mode" badge.
- `AuthMethodInfo.mock` — same transparency, per entry in `methods[]`
  (always `false` for methods with no OTP delivery leg: password, passkey,
  qr, magic_link, sso, oauth).
- System check `stapel_auth.E001` (tag `stapel_auth`): errors at
  `manage.py check` time if `USE_MOCK_SMS_OTP`/`USE_MOCK_EMAIL_OTP` is still
  on with `DEBUG=False` — the prodguard-class gate for "mock OTP shipped to
  production" (`stapel_auth/checks.py`), the same failure shape
  `stapel_core.django.prodguard` catches for secrets/DB passwords.

## [0.7.4] — 2026-07-17

Contract-transparency fix-up: `POST /qr/generate/` accepted `redirect_url`
and `allow_unauthenticated_scanner` but never echoed them back, so a caller
had no way to confirm what was actually recorded against the key (the flow
itself worked — scan-redirect was already covered by tests — but the
response looked like the fields were silently dropped).

### Added
- `QRGenerateResponse` gains `redirect_url` (normalized, `null` if not
  supplied — mirrors what `QRAuthService` actually stores, e.g. a blank
  string collapses to `null`) and `allow_unauthenticated_scanner` (the
  actually-applied boolean, defaulting `false`). Additive — existing fields
  unchanged.

### Changed
- `docs/schema.json` / `docs/capabilities.json` regenerated via
  `make contract` for the new response fields and version bump.

## [0.7.3] — 2026-07-17

Fix-up #2: 0.7.2's regen still baked the *old* version into
`docs/capabilities.json` — `make contract` was run before the version bump
landed in `pyproject.toml`, so the artifact still said 0.7.1 while the
package said 0.7.2. Re-ran `make contract` with 0.7.3 already in
`pyproject.toml`; confirmed `docs/capabilities.json` now says 0.7.3 and the
full suite (1242 passed) is green.

## [0.7.2] — 2026-07-17

Fix-up: 0.7.1's CI/publish failed on contract drift — `docs/capabilities.json`
embeds the package version and wasn't regenerated for the 0.7.1 bump.
Regenerated via `make contract`; no other diff. Contract tests green locally.

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
