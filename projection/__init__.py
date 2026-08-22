"""``stapel_auth.projection`` — the consumer half of the user projection.

A Django app with **no models and no migrations**, installable in any service
that keeps a shadow ``users`` table. It subscribes to the owner's
``user.created`` / ``user.updated`` facts and materialises the local row —
through the very same function the JWT middleware materialises one with, so
the two writers cannot drift.

    INSTALLED_APPS = [
        ...,
        "stapel_auth.projection",   # NOT "stapel_auth" — no auth tables here
    ]

and the service's existing ``manage.py consume_actions`` worker picks the two
topics up (they are ordinary Actions in the registry; nothing new to run).

Install it in a service, not in the identity owner: the handler is inert
wherever ``JWT_CREATE_USERS_FROM_TOKEN`` is ``False``, which is precisely how
the auth service already declares "my ``users`` table is the original, not a
copy". See :mod:`stapel_auth.user_projection` for the owner's side and for
why the pair exists at all.
"""
