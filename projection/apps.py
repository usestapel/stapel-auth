from django.apps import AppConfig


class UserProjectionConfig(AppConfig):
    """Registers the ``user.created`` / ``user.updated`` handlers.

    ``label`` is explicit because the default would be ``projection`` — a
    name generic enough to collide with a host project's own app, for a
    component whose whole job is to be installed in somebody else's service.
    """

    name = "stapel_auth.projection"
    label = "auth_user_projection"
    verbose_name = "Stapel Auth — user projection"

    def ready(self):
        # Importing the module runs the @on_action decorators. Re-imports are
        # no-ops and the action registry dedupes identical handlers, so this
        # is idempotent per process.
        from . import handlers  # noqa: F401

        # And the namespace, so that whoever asks about STAPEL_AUTH in this
        # process gets this module's answer instead of "not set at all".
        #
        # ``stapel_core.conf.registered_settings()`` can only see a namespace
        # whose ``conf`` module has been imported, and a consumer service
        # imports none of stapel-auth eagerly: it installs THIS app, and
        # reaches ``stapel_auth.otp.services`` through a dotted-path seam at
        # request time (stapel-profiles' contact verification). So at
        # ``manage.py check`` time the namespace did not exist, and
        # ``stapel_core.django.presets`` fell back to reading the settings
        # dict — where the mock keys are deliberately absent since 0.38.0,
        # because the posture's stage derives them.
        #
        # The finding that produced: ``stapel_core.presets.W003``, "the
        # declared posture stage is prototype, but nothing prototypical is
        # on: no mock one-time-code channel is enabled", on a service whose
        # mock channel WAS enabled. A check that tells an operator to flip a
        # stage to live while the stub it names is running is worse than no
        # check. Registering the namespace costs one import of a settings
        # object — no models, no views, nothing this app is models-free about
        # — and makes the same answer visible to every walker of that list,
        # including ``stapel_core.conf_checks``' ignored-env-var warning.
        from .. import conf  # noqa: F401
