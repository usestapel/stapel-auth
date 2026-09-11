"""A consumer service's posture check must see this module's settings (0.38.1).

``stapel_auth.projection`` is installed in services that never mount the auth
module — a profiles service keeps a shadow user row and verifies a contact
phone through ``stapel_auth.otp.services`` over a dotted-path seam, resolved at
request time. Nothing imports ``stapel_auth.conf`` during ``django.setup()``
there.

``stapel_core.conf.registered_settings()`` only lists namespaces whose ``conf``
module has been imported, and ``stapel_core.django.presets`` walks that list to
answer "what will this process actually read for STAPEL_AUTH[...]". With the
namespace invisible it fell back to the settings dict, where the mock keys are
deliberately absent since 0.38.0 — the posture's stage derives them — and
reported ``stapel_core.presets.W003``: *"the declared posture stage is
prototype, but nothing prototypical is on: no mock one-time-code channel is
enabled"*, on a service whose mock channel was enabled.

Run in a subprocess on purpose. The question is about what a FRESH process has
imported by the end of ``django.setup()``, and this suite's own process has
imported everything.
"""
import subprocess
import sys
import textwrap

BOOT = textwrap.dedent(
    """
    import json
    import sys

    import django
    from django.conf import settings

    settings.configure(
        DEBUG=False,
        SECRET_KEY="x" * 50,
        ALLOWED_HOSTS=["stand.example.com"],
        INSTALLED_APPS=[
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "stapel_core.django.users",
            "stapel_auth.projection",
        ],
        DATABASES={
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
        },
        EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend",
        USE_TZ=True,
    )
    django.setup()

    from stapel_core.django.presets import public_space

    preset = public_space(stage="prototype")
    settings.STAPEL_POSTURE = preset["STAPEL_POSTURE"]
    settings.STAPEL_AUTH = dict(preset["STAPEL_AUTH"])
    settings.STAPEL_WORKSPACES = dict(preset["STAPEL_WORKSPACES"])

    # ORDER IS THE WHOLE TEST. Both observations are taken BEFORE anything
    # here imports stapel_auth.conf: importing it is precisely what the fix
    # does, so a probe that imported it first would pass with the fix removed
    # — and did, in the first draft of this file.
    imported_by_setup = "stapel_auth.conf" in sys.modules

    from django.core.checks import run_checks

    findings = sorted({f.id for f in run_checks()})

    from stapel_auth.conf import auth_settings

    print(json.dumps({
        "conf_imported_by_setup": imported_by_setup,
        "findings": findings,
        "mock_sms": auth_settings.USE_MOCK_SMS_OTP,
    }))
    """
)


def _boot(cwd) -> dict:
    """Boot the shape above and hand back what it saw.

    ``cwd`` is passed and is never this repository. Under a flat package
    layout this project's own modules sit at the repo root, so a subprocess
    started there has them importable by bare name through ``sys.path[0]`` —
    which quietly imports the very namespace this test is asking about, and
    the gate passes without the code that makes it pass. A service runs from
    ``/app``, not from a library checkout; the test runs from nowhere in
    particular, which is the same thing.
    """
    import json

    done = subprocess.run(
        [sys.executable, "-c", BOOT],
        capture_output=True,
        text=True,
        check=True,
        cwd=str(cwd),
    )
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_projection_app_alone_registers_the_stapel_auth_namespace(tmp_path):
    assert _boot(tmp_path)["conf_imported_by_setup"] is True


def test_a_consumer_service_on_a_prototype_posture_reports_nothing(tmp_path):
    """W003 is the finding this closes; nothing else may appear either."""
    assert _boot(tmp_path)["findings"] == []


def test_and_the_mock_channel_it_could_not_see_really_is_on(tmp_path):
    """The half that makes the silence above mean something."""
    assert _boot(tmp_path)["mock_sms"] is True
