from django.apps import AppConfig


class StapelAuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'stapel_auth'
    label = 'authentication'   # keeps existing migration history / DB tables intact
    verbose_name = 'Stapel Auth'

    def ready(self):
        import warnings
        from django.conf import settings
        from django.utils.module_loading import import_string
        from stapel_core.oauth import register_provider
        from .conf import auth_settings

        if not auth_settings.FRONTEND_URL:
            warnings.warn(
                "stapel-auth: FRONTEND_URL is not set. "
                "Set STAPEL_AUTH = {'FRONTEND_URL': '...'} or FRONTEND_URL env var. "
                "Redirects after SSO/magic link/QR login will not work correctly.",
                stacklevel=2,
            )

        classes = list(auth_settings.OAUTH_PROVIDER_CLASSES)
        if getattr(settings, 'DEBUG', False):
            classes.append('stapel_auth.oauth_providers.TestProvider')

        for cls_path in classes:
            register_provider(import_string(cls_path)())

        # In monolith mode (no GDPR_COLLECTING_SERVICES), register the GDPR provider
        # in-process so the orchestrator can call it directly.
        # In microservices mode the bus consumer (management/commands/consume_gdpr.py) handles it.
        if not getattr(settings, 'GDPR_COLLECTING_SERVICES', None):
            from stapel_core.gdpr import gdpr_registry
            from .gdpr import AuthGDPRProvider
            gdpr_registry.register(AuthGDPRProvider())
