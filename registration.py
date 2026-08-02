"""The registration gate — the single place a NEW account is allowed to be born.

Why this module exists (#86). The ``AUTH_*_REGISTRATION`` settings existed
long before it, and switching them off changed nothing for the flows that
matter, because the check sat in the wrong place::

    # otp/views.py, email_request
    if (not auth_settings.AUTH_EMAIL_LOGIN
            and not auth_settings.AUTH_EMAIL_REGISTRATION):
        return error_403_forbidden()

That is an ``and``: it refuses only when the channel is off *entirely*. With
login on and registration off — the whole point of "invite-only, everybody
already here keeps signing in" — the request handler accepted any address,
sent a code, and ``email_verify`` then ran an unconditional
``User.objects.create``. The flag was a label on a door that was never
locked.

So the gate moved to where a user is CREATED, not to where a code is asked
for. Every creation site in the module now goes through
:func:`require_registration_open` (or the ``registration_open`` predicate),
which makes the invariant checkable by reading one grep: an account is born
only if its method's axis says so.

**What is NOT gated, on purpose.** These are the owner's own doors, and
closing them would leave a deployment with no way to create accounts at all:

* ``auth.provision_user`` (functions.py) — the comm function an org uses to
  hand out namespaced logins; the canonical "only the owner makes accounts"
  path;
* ``POST /admin-users/`` (admin/views.py) — service API key or staff only;
* ``LoginGrantService.exchange(create_if_missing=True)`` — a grant is minted
  server-side by a trusted issuer (the workspaces invite flow), never by the
  person signing in, and ``AUTH_LOGIN_GRANT`` is off by default;
* ``POST /anonymous/`` — a guest session is not an account; it has its own
  ``AUTH_ANONYMOUS`` axis. Promoting a guest into a real account *is*
  registration and IS gated (otp verify / oauth / sso promote branches).

**The oracle question** (``AUTH_REGISTRATION_CLOSED_BEHAVIOR``). Refusing
only unknown addresses turns the OTP endpoints into an existence oracle: the
difference between the two answers enumerates who works at the company. The
three honest options each cost something, so the choice is a setting rather
than a rewrite:

``'silent'`` (default)
    Same answer for everybody. An unknown target gets the ordinary
    "code sent" envelope and the ordinary rate-limit bookkeeping — the code
    is generated and stored, but nothing is delivered and the value is
    random (never the mock code), so no one can ever present it. Verify then
    fails as an ordinary wrong code. No oracle; the cost is that a person who
    typos their address waits for a letter that will not come.
``'request'``
    Refuse at ``*/request`` with 403 ``error.403.registration_closed``. The
    loudest, most usable answer — no pointless code is sent and the frontend
    can say "this address has no account" — and a full enumeration oracle.
``'verify'``
    Send the code as usual, refuse at ``*/verify`` with 403. The oracle moves
    one step later (a stranger still receives mail from you), which is worse
    than ``'request'`` on cost and only marginally better on exposure. It
    exists because it is the smallest possible change from the pre-#86
    behavior, for hosts that already built a UI around the code arriving.

The default is the closed one: a deployment that shuts registration to keep
its member list private should not have to also discover a setting to make
that true.

The behavior knob governs the enumerable surfaces only — email and phone
OTP. OAuth and SSO refuse a fresh identity outright (403 / an
``?error=registration_closed`` redirect), because learning "this Google
account is not registered here" requires already controlling that Google
account: there is nothing to enumerate.
"""

#: Methods that own an ``AUTH_<METHOD>_REGISTRATION`` axis.
REGISTRATION_METHODS = ('email', 'phone', 'oauth', 'sso', 'password')

BEHAVIOR_SILENT = 'silent'
BEHAVIOR_REQUEST = 'request'
BEHAVIOR_VERIFY = 'verify'

#: Valid values of ``AUTH_REGISTRATION_CLOSED_BEHAVIOR``, closed-first.
CLOSED_BEHAVIORS = (BEHAVIOR_SILENT, BEHAVIOR_REQUEST, BEHAVIOR_VERIFY)


class RegistrationClosed(Exception):
    """A new account would have to be created and its axis is off.

    Raised by the creation helpers that sit deep inside a resolve step
    (``_resolve_oauth_user``, ``SSOUserService.get_or_create_user``) where
    returning a DRF response is not an option; the view catches it and turns
    it into the surface-appropriate refusal.
    """

    def __init__(self, method: str):
        self.method = method
        super().__init__(f'registration closed for method {method!r}')


def registration_open(method: str) -> bool:
    """Is ``AUTH_<METHOD>_REGISTRATION`` on?"""
    from stapel_auth.conf import auth_settings

    return bool(getattr(auth_settings, f'AUTH_{method.upper()}_REGISTRATION'))


def require_registration_open(method: str) -> None:
    """Raise :class:`RegistrationClosed` when *method* may not create accounts."""
    if not registration_open(method):
        raise RegistrationClosed(method)


def closed_behavior() -> str:
    """Normalized ``AUTH_REGISTRATION_CLOSED_BEHAVIOR``.

    An unrecognized value degrades to the CLOSED end (``'silent'``) rather
    than to the permissive one — a typo in a deploy config must not quietly
    hand out an enumeration oracle.
    """
    from stapel_auth.conf import auth_settings

    value = str(auth_settings.AUTH_REGISTRATION_CLOSED_BEHAVIOR or '').strip().lower()
    return value if value in CLOSED_BEHAVIORS else BEHAVIOR_SILENT
