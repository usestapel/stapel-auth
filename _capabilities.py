"""stapel-auth capabilities.json emitter — thin shim over stapel_tools.capabilities.

The axis rules below are module-level on purpose. ``tests/test_contract.py``
re-runs the emitter with deliberately broken curated metadata to prove the
gap fails loudly, and it used to carry its own copy of these rules — which
meant a new axis passed the emitter and failed the test that was supposed to
be checking the emitter. A second copy of a rule is a second answer to the
same question; the test imports this one now.
"""
from pathlib import Path

from stapel_tools.capabilities import axis_group_rules, run_capabilities_cli

#: Which settings keys are configuration AXES at all (vs plain values).
def IS_AXIS(key):  # noqa: N802 - a rule, exported under the name it is used by
    return key.startswith("AUTH_") or key.endswith("_STEP_UP")


#: Axis -> capability group. Suffix rules cover the families; the exact map
#: is for the axes that have no suffix to ride.
AXIS_GROUP = axis_group_rules(
    exact={
        "AUTH_ANONYMOUS": "auth.anonymous",
        "AUTH_TOTP": "auth.mfa",
        # Login-surface axis without the *_LOGIN suffix to ride:
        # gates the grant-exchange endpoint (workspaces §B3).
        "AUTH_LOGIN_GRANT": "auth.login",
        # Registration-policy axis (no *_REGISTRATION suffix to ride):
        # governs whether a password-only sign-up deanonymizes.
        "AUTH_PASSWORD_DEANONYMIZES": "auth.registration",
        # Same group, also without the suffix to ride: how a CLOSED
        # registration answers a stranger (#86, registration.py).
        "AUTH_REGISTRATION_CLOSED_BEHAVIOR": "auth.registration",
        # Same group, also without the suffix to ride: whether a
        # registration may store the ad click that produced the
        # account (attribution.py).
        "AUTH_SIGNUP_ATTRIBUTION": "auth.registration",
    },
    suffix={
        "_REGISTRATION": "auth.registration",
        "_LOGIN": "auth.login",
        "_STEP_UP": "auth.stepup",
        "_PLACEMENT": "auth.placement",
    },
)


def main(argv=None):
    from stapel_auth._codegen import _configure

    _configure()
    from stapel_auth.conf import DEFAULTS
    from stapel_auth.urls import GATE_REGISTRY

    return run_capabilities_cli(
        argv,
        repo=Path(__file__).resolve().parent,
        canonical_prefix="/auth/api/v1",
        defaults=DEFAULTS,
        registry=GATE_REGISTRY,
        is_axis=IS_AXIS,
        axis_group=AXIS_GROUP,
        prog="stapel-auth-capabilities",
    )


if __name__ == "__main__":
    raise SystemExit(main())
