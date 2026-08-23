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

        # The erasure protocol (stapel-gdpr 0.5.0+), implemented once in
        # stapel-core: gdpr.erasure.requested -> erase -> gdpr.section.erased
        # with a deterministic receipt inside the erase's transaction, plus
        # the gdpr.owner.probe answer from the same module. Unconditional —
        # auth was the fleet's only declared owner that answered no probe, so
        # owners-health reported `auth: alive=false` in a deployment where the
        # erasure worked fine. Liveness is answered by the subscriber that
        # erases or it is not evidence of anything.
        #
        # Auth is also the module that HOSTS stapel-gdpr, so both this
        # subscriber and the in-process provider above run in one process for
        # one account erasure. Registering both does not double-receipt: the
        # orchestrator's local receipt skips a part that is already done and
        # mark_section_erased excludes done parts (tests/test_gdpr_owner.py
        # pins exactly that).
        from stapel_core.gdpr import register_gdpr_owner
        from .erasure import OWNER, SUBJECT_TYPES, erase_subject
        register_gdpr_owner(OWNER, SUBJECT_TYPES, erase_subject)

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
