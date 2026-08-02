# stapel-auth

[![CI](https://img.shields.io/github/actions/workflow/status/usestapel/stapel-auth/ci.yml?branch=main&logo=github&label=CI)](https://github.com/usestapel/stapel-auth/actions/workflows/ci.yml?query=branch%3Amain)
[![coverage](https://img.shields.io/codecov/c/github/usestapel/stapel-auth?branch=main&logo=codecov&label=coverage)](https://app.codecov.io/gh/usestapel/stapel-auth)
[![pypi](https://img.shields.io/pypi/v/stapel-auth?logo=pypi&logoColor=white&label=pypi)](https://pypi.org/project/stapel-auth/)
[![downloads](https://static.pepy.tech/badge/stapel-auth/month)](https://pepy.tech/project/stapel-auth)
[![python](https://img.shields.io/pypi/pyversions/stapel-auth?logo=python&logoColor=white)](https://pypi.org/project/stapel-auth/)
[![license](https://img.shields.io/github/license/usestapel/stapel-auth)](https://github.com/usestapel/stapel-auth/blob/main/LICENSE)
[![llms.txt](https://img.shields.io/badge/llms.txt-blue)](https://github.com/usestapel/stapel-auth/blob/main/docs/llms.txt)

> Full-featured authentication — JWT, passkeys (WebAuthn), TOTP, QR login, OAuth2, SSO (SAML/OIDC), email link, phone OTP

Part of the [Stapel framework](https://github.com/usestapel) — composable Django apps for building production-grade platforms.

**Flow docs (SA-documents):** [Flows (EN)](docs/flows/en/README.md) · [Флоу (RU)](docs/flows/ru/README.md)

**Error reference:** [Errors (EN)](docs/errors.en.md) · [Ошибки (RU)](docs/errors.ru.md)

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

## License

MIT — see [LICENSE](LICENSE)
