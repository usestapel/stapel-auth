# stapel-auth

> Full-featured authentication — JWT, passkeys (WebAuthn), TOTP, QR login, OAuth2, SSO (SAML/OIDC), magic link, phone OTP

Part of the [Stapel framework](https://github.com/usestapel) — composable Django apps for building production-grade platforms.

## Installation

```bash
pip install stapel-auth
```

## Quick start

```python
# settings.py
INSTALLED_APPS = [
    ...
    'stapel_auth',
]
```

## Bus events

### Emits
| `user.session_created` | [schema](schemas/emits/user.session_created.json) | User successfully authenticated and a new session was created. |
| `user.session_revoked` | [schema](schemas/emits/user.session_revoked.json) | A user session was revoked (logout or admin action). |

## Contributing

The source for this package lives inside the [ironmemo-backend](https://github.com/UCSoftworks) monorepo as a git submodule.

## License

MIT — see [LICENSE](LICENSE)
