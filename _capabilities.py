"""stapel-auth capabilities.json emitter — thin shim over stapel_tools.capabilities."""
from pathlib import Path

from stapel_tools.capabilities import axis_group_rules, run_capabilities_cli


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
        is_axis=lambda k: k.startswith("AUTH_") or k.endswith("_STEP_UP"),
        axis_group=axis_group_rules(
            exact={
                "AUTH_ANONYMOUS": "auth.anonymous",
                "AUTH_TOTP": "auth.mfa",
                # Registration-policy axis (no *_REGISTRATION suffix to ride):
                # governs whether a password-only sign-up deanonymizes.
                "AUTH_PASSWORD_DEANONYMIZES": "auth.registration",
            },
            suffix={
                "_REGISTRATION": "auth.registration",
                "_LOGIN": "auth.login",
                "_STEP_UP": "auth.stepup",
                "_PLACEMENT": "auth.placement",
            },
        ),
        prog="stapel-auth-capabilities",
    )


if __name__ == "__main__":
    raise SystemExit(main())
