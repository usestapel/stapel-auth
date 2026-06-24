from django.apps import AppConfig


class StapelAuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'stapel_auth'
    label = 'authentication'   # keeps existing migration history / DB tables intact
    verbose_name = 'Stapel Auth'

    def ready(self):
        from .conf import auth_settings
        import warnings

        if not auth_settings.FRONTEND_URL:
            warnings.warn(
                "stapel-auth: FRONTEND_URL is not set. "
                "Set STAPEL_AUTH = {'FRONTEND_URL': '...'} or FRONTEND_URL env var. "
                "Redirects after SSO/magic link/QR login will not work correctly.",
                stacklevel=2,
            )
        from stapel_core.gdpr import gdpr_registry
        from .gdpr import AuthGDPRProvider
        gdpr_registry.register(AuthGDPRProvider())
