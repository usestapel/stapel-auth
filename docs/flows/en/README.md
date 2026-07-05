# Flows

| ID | Name | Steps |
|---|---|---|
| [`auth.password_login`](auth.password_login.md) | Password login (+ optional TOTP) | 3 |
| [`auth.passwordless_login`](auth.passwordless_login.md) | Passwordless login (email OTP) | 4 |
| [`auth.step_up_verification`](auth.step_up_verification.md) | Step-up verification on a protected endpoint (reference flow) | 7 |

## Endpoint → flow

- `GET /verification/<str:challenge_id>/` → auth.step_up_verification
- `GET /verification/preferences/` → auth.step_up_verification
- `POST /email/request/` → auth.passwordless_login
- `POST /email/verify/` → auth.passwordless_login
- `POST /password/login/` → auth.password_login
- `POST /totp/challenge/verify/` → auth.password_login
- `POST /verification/<str:challenge_id>/complete/` → auth.step_up_verification
- `POST /verification/<str:challenge_id>/initiate/` → auth.step_up_verification
- `PUT /verification/preferences/` → auth.step_up_verification
