**English** · [Русский](../ru/README.md)

# Flows

### [First login of an org-provisioned account](auth.first_login.md)

`auth.first_login` · 5 steps · Actors: Org-provisioned user

An organization admin provisioned the account (auth.provision_user: namespaced username org_slug/local, org-set or server-generated password, a first-login policy flag). The first password login returns FIRST_LOGIN_REQUIRED with a 10-minute challenge_token instead of a session: requires=password_change routes to the forced password change, requires=mfa_enroll to a limited enroll-only session in which only TOTP setup/confirm, passkey registration and logout are allowed. Completing the step clears the flag and yields a full session; when both flags are set, the password change chains straight into the mfa_enroll challenge.

### [Password login (+ optional TOTP)](auth.password_login.md)

`auth.password_login` · 3 steps · Actors: Anonymous user

The user signs in with a login (email/username) and password. The endpoint is enabled by the AUTH_PASSWORD_LOGIN setting. Failed attempts lead to progressive lockout (423 with retry_after). If the user has TOTP enabled and the PASSWORD_LOGIN_STEP_UP setting is active (default: yes), TOTP_REQUIRED with a challenge_token is returned instead of tokens — the session is issued only after the authenticator code is verified.

### [Passwordless login (email OTP)](auth.passwordless_login.md)

`auth.passwordless_login` · 4 steps · Actors: Anonymous user

An anonymous user receives a one-time code by email and exchanges it for a JWT session (cookies + a token pair in the response body). Requesting the code again is rate-limited (30 seconds between sends; 429/422 when exceeded); after a series of wrong codes the address is temporarily locked. If the address was not registered, the first successful login creates a new user (status=REGISTERED instead of LOGGED_IN).

### [Step-up verification on a protected endpoint (reference flow)](auth.step_up_verification.md)

`auth.step_up_verification` · 7 steps · Actors: Authenticated user

THE reference flow of the step-up verification contract (stapel_core.verification, see flows-and-verification.md §2) — clients of any service implement it once and reuse it for every endpoint protected by @requires_verification. The cycle: the protected endpoint responds 403 with a structured verification envelope (challenge_id, scope, factors, expires_at) → the client reads the challenge, picks an available factor (factors are interchangeable: otp_email, otp_phone, totp, passkey all close one challenge), initiates it and completes the check → repeats the original request. The grant is stored server-side (cache, user+scope key, TTL=max_age); stateless clients may instead send the X-Verification-Token header from the completion response. After MAX_ATTEMPTS wrong attempts the challenge burns out (423) — call the original endpoint again for a new challenge.

## Endpoint → flow

- `GET /auth/api/v1/verification/<str:challenge_id>/` → auth.step_up_verification
- `GET /auth/api/v1/verification/preferences/` → auth.step_up_verification
- `POST /auth/api/v1/email/request/` → auth.passwordless_login
- `POST /auth/api/v1/email/verify/` → auth.passwordless_login
- `POST /auth/api/v1/mfa/enroll/exchange/` → auth.first_login
- `POST /auth/api/v1/password/forced-change/` → auth.first_login
- `POST /auth/api/v1/password/login/` → auth.first_login, auth.password_login
- `POST /auth/api/v1/totp/challenge/verify/` → auth.password_login
- `POST /auth/api/v1/totp/setup/confirm/` → auth.first_login
- `POST /auth/api/v1/verification/<str:challenge_id>/complete/` → auth.step_up_verification
- `POST /auth/api/v1/verification/<str:challenge_id>/initiate/` → auth.step_up_verification
- `PUT /auth/api/v1/verification/preferences/` → auth.step_up_verification
