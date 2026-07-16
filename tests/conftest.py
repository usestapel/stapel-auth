def pytest_configure(config):
    # Bootstrap a minimal Celery app so shared_task decorators have a configured
    # app with ALWAYS_EAGER=True before Django settings are loaded.
    from celery import Celery

    _celery = Celery("stapel_auth_test")
    _celery.config_from_object(
        {
            "task_always_eager": True,
            "task_eager_propagates": True,
            "broker_url": "memory://",
            "result_backend": "cache+memory://",
        }
    )
    _celery.set_default()

    from django.conf import settings

    if settings.configured:
        return

    settings.configure(
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
        ROOT_URLCONF="stapel_auth.urls_v1",  # bare v1 set; the v1/ mount itself is covered by test_mounting_urls
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
        REST_FRAMEWORK={
            "DEFAULT_AUTHENTICATION_CLASSES": [
                "stapel_core.django.jwt.authentication.JWTCookieAuthentication",
            ],
            # No IsServiceRequest / IsSuperUser in tests — endpoints handle their own auth
            "DEFAULT_PERMISSION_CLASSES": [],
            "EXCEPTION_HANDLER": "stapel_core.django.api.errors.stapel_exception_handler",
        },
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
    import django
    django.setup()
