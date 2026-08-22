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
