"""Single-module Django settings for stapel-auth's harnesses.

Single source of truth for the ``settings.configure(...)`` block shared by:

  - the pytest suite (``conftest.py``) — mounts auth on its *bare* urlconf
    (``stapel_auth.urls``), the historical test layout; and
  - the contract-emission harness (``_codegen.py`` / ``make contract``) — mounts
    auth on its *canonical* public API prefix (``stapel_auth.codegen_urls`` →
    ``auth/api/``) and enables drf-spectacular, so the emitted ``schema.json`` /
    ``flows.json`` paths are byte-identical to the monolith aggregate's auth slice
    (contract-pipeline.md §2).

Keeping one copy here means the harness and the tests can never drift in their
``INSTALLED_APPS`` / ``MIDDLEWARE`` / mock config — the exact hazard
contract-pipeline.md §3 calls out ("~30 lines that *reference* the already-existing
config, not a second copy of it").
"""
from __future__ import annotations


def settings_kwargs(
    *,
    root_urlconf: str = "stapel_auth.urls",
    contract: bool = False,
) -> dict:
    """Return the ``settings.configure(**kwargs)`` for a single-module auth instance.

    ``root_urlconf`` selects the mount: bare (``stapel_auth.urls``) for the test
    suite, canonical-prefix (``stapel_auth.codegen_urls`` → ``auth/api/``) for
    contract emission.

    ``contract=True`` swaps in the *production* ``REST_FRAMEWORK`` (the canonical
    stapel-core config, inlined as plain dotted paths — importing it would trip the
    same chicken-and-egg as spectacular). This matters for byte-identity: the
    monolith emits with ``DEFAULT_SCHEMA_CLASS=PermissionAwareAutoSchema`` and the
    real permission/renderer classes, and DRF caches ``REST_FRAMEWORK`` on first
    access, so it must be right at ``configure()`` time — a post-hoc assignment is
    too late. The test suite keeps its permissive config (``contract=False``).

    ``SPECTACULAR_SETTINGS`` is deliberately *not* set. drf-spectacular builds its
    settings singleton at *import* time (``getattr(settings, 'SPECTACULAR_SETTINGS',
    {})`` at module load), before a ``configure()``-based harness can populate it,
    so a Django-level ``SPECTACULAR_SETTINGS`` is silently ignored and the emitter
    runs on drf **defaults**. That is exactly what the monolith aggregate emits with
    too — its ``SPECTACULAR_SETTINGS`` is ignored the same way (the committed
    ``schema.json`` has ``info.title=""``, no ``bearerAuth`` scheme, no
    ``x-stapel-*`` extensions). The one knob that still must be forced,
    ``SCHEMA_PATH_PREFIX``, is patched on the singleton directly by the harness
    (see ``_codegen._configure``).
    """
    if contract:
        # Mirror stapel_core.django.settings.REST_FRAMEWORK exactly (the config the
        # monolith emits under). Inlined, not imported, to dodge the import-time
        # settings read; kept in lockstep by test_contract.py's identity gate.
        rest_framework = {
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "stapel_core.django.jwt.authentication.JWTCookieAuthentication",
            ],
            "DEFAULT_PERMISSION_CLASSES": [
                "stapel_core.django.api.permissions.IsServiceRequest",
                "stapel_core.django.api.permissions.IsSuperUser",
            ],
            "DEFAULT_RENDERER_CLASSES": [
                "rest_framework.renderers.JSONRenderer",
                "rest_framework.renderers.BrowsableAPIRenderer",
            ],
            "DEFAULT_SCHEMA_CLASS": "stapel_core.django.openapi.schemas.PermissionAwareAutoSchema",
            "EXCEPTION_HANDLER": "stapel_core.django.api.errors.stapel_exception_handler",
        }
    else:
        rest_framework = {
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "stapel_core.django.jwt.authentication.JWTCookieAuthentication",
            ],
            # No IsServiceRequest / IsSuperUser in tests — endpoints handle their own auth
            "DEFAULT_PERMISSION_CLASSES": [],
            "EXCEPTION_HANDLER": "stapel_core.django.api.errors.stapel_exception_handler",
        }
    kwargs = dict(
        SECRET_KEY="test-secret-key-32-chars-minimum!!",
        DEBUG=True,
        ALLOWED_HOSTS=["*"],
        INSTALLED_APPS=[
            "django.contrib.admin",
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "django.contrib.sessions",
            "django.contrib.messages",
            "django.contrib.staticfiles",
            "rest_framework",
            "drf_spectacular",
            "stapel_core.django.apps.CommonDjangoConfig",
            "stapel_core.django.users",
            "stapel_core.django.outbox",
            "social_django",
            "stapel_auth",
            "stapel_gdpr",
        ],
        MIDDLEWARE=[
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.middleware.common.CommonMiddleware",
            "stapel_core.django.jwt.middleware.CsrfExemptAPIMiddleware",
            "django.middleware.csrf.CsrfViewMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "stapel_core.django.jwt.middleware.JWTAuthMiddleware",
            "stapel_core.django.admin.redirect.AdminLoginRedirectMiddleware",
            "stapel_core.django.jwt.middleware.ServiceAPIKeyMiddleware",
            "django.contrib.messages.middleware.MessageMiddleware",
            "django.middleware.clickjacking.XFrameOptionsMiddleware",
        ],
        TEMPLATES=[
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "DIRS": [],
                "APP_DIRS": True,
                "OPTIONS": {
                    "context_processors": [
                        "django.template.context_processors.debug",
                        "django.template.context_processors.request",
                        "django.contrib.auth.context_processors.auth",
                        "django.contrib.messages.context_processors.messages",
                        "social_django.context_processors.backends",
                        "social_django.context_processors.login_redirect",
                    ],
                },
            }
        ],
        AUTH_USER_MODEL="users.User",
        ROOT_URLCONF=root_urlconf,
        DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
        USE_TZ=True,
        DATABASES={
            "default": {
                "ENGINE": "django.db.backends.sqlite3",
                "NAME": ":memory:",
            }
        },
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
            }
        },
        # In-memory bus — no Kafka/Redis broker needed
        STAPEL_BUS_BACKEND="stapel_core.bus.backends.memory.MemoryBus",
        # Sync Celery — tasks run inline, broker never contacted
        CELERY_TASK_ALWAYS_EAGER=True,
        CELERY_TASK_EAGER_PROPAGATES=True,
        CELERY_BROKER_URL="memory://localhost//",
        CELERY_RESULT_BACKEND="cache+memory://",
        # Mock OTP — tests use code '0000'
        USE_MOCK_SMS_OTP=True,
        USE_MOCK_EMAIL_OTP=True,
        MOCK_OTP_CODE="0000",
        # QR/magic-link redirects
        FRONTEND_URL="http://localhost:3000",
        BACKEND_URL="http://localhost:8000",
        WORKSPACES_SERVICE_URL="http://localhost:8003",
        # JWT — minimal config for tests
        JWT_SECRET_KEY="test-jwt-secret-key-for-testing-only",
        JWT_ALGORITHM="HS256",
        JWT_AUDIENCE="stapel",
        JWT_ISSUER="stapel-auth",
        JWT_AUTO_REFRESH_ENABLED=True,
        JWT_REFRESH_ALLOWED=True,
        JWT_CREATE_USERS_FROM_TOKEN=False,
        # Social auth backends (OAuth SSO tests)
        AUTHENTICATION_BACKENDS=[
            "social_core.backends.google.GoogleOAuth2",
            "social_core.backends.github.GithubOAuth2",
            "django.contrib.auth.backends.ModelBackend",
        ],
        SOCIAL_AUTH_GOOGLE_OAUTH2_KEY="",
        SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET="",
        SOCIAL_AUTH_GITHUB_KEY="",
        SOCIAL_AUTH_GITHUB_SECRET="",
        # Twilio — empty values, SMS is mocked in tests
        TWILIO_ACCOUNT_SID="",
        TWILIO_AUTH_TOKEN="",
        TWILIO_PHONE_NUMBER="",
        TWILIO_VERIFY_SERVICE_SID="",
        REST_FRAMEWORK=rest_framework,
        # Service settings
        URL_PREFIX="auth/",
        SERVICE_NAME="Iron Auth Test",
        KAFKA_BOOTSTRAP_SERVERS="",
        # Skip migrations — create tables directly from models
        MIGRATION_MODULES={
            "users": None,
            "authentication": None,
            "gdpr": None,
        },
    )
    return kwargs


# The multi-module common path prefix drf-spectacular auto-detects in the monolith
# aggregate. Forced on the drf-spectacular settings singleton by the harness so a
# single-module instance derives the same operationIds (see _codegen._configure and
# the SCHEMA_PATH_PREFIX note above). Uniform across all five pair-backends.
CODEGEN_SCHEMA_PATH_PREFIX = "/"
