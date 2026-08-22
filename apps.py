from django.apps import AppConfig


class StapelAuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'stapel_auth'
    label = 'authentication'   # keeps existing migration history / DB tables intact
    verbose_name = 'Stapel Auth'

    def ready(self):
        from django.conf import settings
        from django.utils.module_loading import import_string
        from stapel_core.oauth import register_provider
        from .conf import auth_settings

        classes = list(auth_settings.OAUTH_PROVIDER_CLASSES)
        if getattr(settings, 'DEBUG', False):
            classes.append('stapel_auth.oauth_providers.TestProvider')

        for cls_path in classes:
            register_provider(import_string(cls_path)())

        # Step-up verification factors: the mechanism (challenge/grant
        # stores, @requires_verification) lives in stapel-core; the concrete
        # factor implementations on top of the auth services are registered
        # here. register_factor is idempotent per factor id.
        from stapel_core.verification import register_factor
        from .verification_factors import DEFAULT_FACTOR_CLASSES
        for factor_cls in DEFAULT_FACTOR_CLASSES:
            register_factor(factor_cls())

        # comm Function providers (auth.verification.policy). Importing the
        # module runs the @function decorators; re-imports are no-ops and
        # re-registering the same handler object is idempotent.
        from . import functions  # noqa: F401

        # In monolith mode (no GDPR_COLLECTING_SERVICES), register the GDPR provider
        # in-process so the orchestrator can call it directly.
        # In microservices mode the bus consumer (management/commands/consume_gdpr.py) handles it.
        if not getattr(settings, 'GDPR_COLLECTING_SERVICES', None):
            from stapel_core.gdpr import gdpr_registry
            from .gdpr import AuthGDPRProvider
            gdpr_registry.register(AuthGDPRProvider())

        # Account activation observer (#92): announces the real is_active
        # True<->False transition as user.deactivated / user.reactivated,
        # whoever flipped the flag (service call, admin checkbox, shell).
        from .activation import register_activation_observer
        register_activation_observer()

        # User projection observer: announces every identity row this module
        # owns as user.created / user.updated, so a service holding a shadow
        # users table can materialise a user who never presented a token to
        # it (chat participant_ids, an assignee, a recipient). The consumer
        # half is the installable app stapel_auth.projection.
        from .user_projection import register_user_projection_observer
        register_user_projection_observer()

        # System check: USE_MOCK_*_OTP left on with DEBUG=False (checks.py).
        from . import checks as _checks  # noqa: F401
