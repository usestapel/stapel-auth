## What this is

Authentication is the part of a product that everyone builds and nobody wants
to own: a dozen sign-in methods, each with its own rate limits, lockouts,
notification rules and recovery paths, plus the security surface underneath
them — sessions, devices, audit, step-up. `stapel-auth` is that whole area as
one installable Django app, with every method behind a settings flag so a
product ships only the ones it wants.

The shape to keep in mind: **sign-in methods are axes, not forks.** Email OTP,
phone OTP, password (+ TOTP), OAuth, enterprise SSO, magic link, QR hand-off,
passkeys and guest access are each one `AUTH_*` flag. Turning a flag off
unmounts its endpoints *and* removes it from the capabilities response the
frontend reads — so the login screen changes with the setting, not with a
frontend release. `GET /capabilities/` is the contract for that: availability,
placement, interaction and icon per method, plus OTP code length, TTL and
resend cooldown, so no client hardcodes a number this module owns.

## Quick start

```python
# settings.py
INSTALLED_APPS = [
    # ...
    "stapel_auth",
]

STAPEL_AUTH = {
    "AUTH_EMAIL": True,          # email OTP sign-in
    "AUTH_PASSWORD_LOGIN": True,  # password (+ TOTP step-up when enrolled)
    "AUTH_ANONYMOUS": False,      # no guest accounts
}
```

```python
# urls.py
path("auth/", include("stapel_auth.urls")),
```

```bash
python manage.py migrate
```

Behind a reverse proxy, tell the framework which header carries the client
IP — rate limits, lockouts and the IP in every audit row are keyed on it, and
by default only `REMOTE_ADDR` (i.e. the proxy) is trusted:

```python
# ONLY if the edge overwrites this header on every request
# (nginx: proxy_set_header X-Real-IP $remote_addr)
STAPEL_NETINTEL = {"TRUSTED_PROXY_HEADER": "HTTP_X_REAL_IP"}
```

`manage.py check` says so too: `stapel_auth.W005` when a proxy is declared but
no header is, `stapel_auth.W006` when the named header is one proxies usually
*append* to (`X-Forwarded-For`), where the first element is whatever the caller
wrote.

If your frontend posts provider access tokens to `POST /oauth/login/` rather
than using the redirect flow, pin which OAuth clients may vouch for an
identity — a token is a bearer credential for the app it was minted for, so an
unpinned endpoint accepts one minted for somebody else's app:

```python
STAPEL_AUTH = {
    "OAUTH_ACCEPTED_AUDIENCES": {
        # a LIST — Google issues one client ID per platform
        "google": ["<web>.apps.googleusercontent.com",
                   "<ios>.apps.googleusercontent.com"],
    },
}
```

Google, Facebook and GitHub can prove a token's audience; Zoom and the
not-yet-implemented providers cannot, so they refuse that endpoint and keep
working through the redirect flow. `W007`/`E008`/`W009`/`W010` report which
case each configured provider is in.

Every configuration axis, its default and the operations it gates are listed
in [`docs/capabilities.json`](https://github.com/usestapel/stapel-auth/blob/main/docs/capabilities.json) — the same document the
table above is generated from, and the one an agent reads before writing code
against this module.

## Step-up verification

Any endpoint in any module can demand a fresh proof of identity by decorating
itself with `@requires_verification` (from `stapel_core.verification`). This
module registers the factors that satisfy it — `otp_email`, `otp_phone`,
`totp`, `passkey` — and hosts the challenge endpoints.

The factors are interchangeable by design: a challenge names a scope and the
factors currently available to that user, and *any* of them closes it. A
client implements the cycle once (403 with a challenge envelope → pick a
factor → initiate → complete → repeat the original request) and reuses it for
every protected endpoint in the product, forever. The reference walkthrough is
the `auth.step_up_verification` flow.

## Sessions, devices and recovery

Sessions are JWT (cookie plus a token pair) with a tracked `UserSession` per
device, so "sign out everywhere" and "revoke this device" are real operations
rather than a token TTL. Suspicious sessions (new device, unexpected IP) are
detected, notified and revocable from the notification itself.

Authenticator changes — email, phone or TOTP — run through one model and one
set of tasks, in two speeds: instant, when the user can prove control of the
current authenticator, and delayed, when they cannot. There is no third
speed: a code sent to a *new* address can set a first email or phone, never
replace a verified one, so a stolen session cannot quietly move the recovery
address out of the owner's reach. The delayed path is the
one that matters after a lost phone: it notifies the verified contact on day
1, 7 and 13 and completes on day 14, which gives an attacker who has the inbox
but not the device two weeks of loud warnings and the real owner two weeks to
cancel.

## Enterprise SSO

SAML SP and OIDC RP, configured per organization in the database rather than
in settings — a tenant onboards without a deploy. Users provisioned by an org
admin land in the `auth.first_login` flow: the first password login returns a
short-lived challenge instead of a session, routing to a forced password change
and/or MFA enrolment before anything else is reachable.

## Bus events

Emitted through `stapel_core.comm` (transactional outbox — the event leaves if
and only if your transaction commits):

| Event | Payload | When |
|---|---|---|
| `user.session_created` | [schema](https://github.com/usestapel/stapel-auth/blob/main/schemas/emits/user.session_created.json) | A user authenticated and a session was created |
| `user.session_revoked` | [schema](https://github.com/usestapel/stapel-auth/blob/main/schemas/emits/user.session_revoked.json) | A session was revoked (logout or admin action) |

## Extension points

Providers, models and policies are replaced by dotted path, never by fork —
additional OAuth providers, a custom re-registration model, serializer and
permission seams. [`MODULE.md`](https://github.com/usestapel/stapel-auth/blob/main/MODULE.md) is the full agent-facing map;
`docs/capabilities.json` carries the machine-readable list.

## Development

```bash
pip install -e . && pip install pytest pytest-django pytest-cov ruff
./setup-hooks.sh
pytest tests/
```
