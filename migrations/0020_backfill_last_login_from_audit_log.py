"""Backfill ``User.last_login`` from this module's own audit log.

The column was never written by any JWT login path (Django stamps it from the
``user_logged_in`` signal, which only session login sends — see
``sessions.services.stamp_last_login``, the fix that stops the bleeding).
Releases stamp it from now on; this fills in the accounts that already logged
in while nothing was looking.

The evidence is ``auth_audit_log``, which recorded every one of those logins
correctly the whole time: the latest successful-login row per user becomes
that user's ``last_login``.

Boundaries, all deliberate:

* **NULLs only.** A non-NULL value is either a real session login or an
  already-backfilled one; either way it is at least as good as what the audit
  log would say, and overwriting it could move a timestamp *backwards*.
* **No row, no stamp.** An account with no successful-login event is left
  NULL — NULL is the honest answer for "we have no evidence this account ever
  logged in", and inventing ``date_joined`` or ``now()`` would turn a
  knowable gap into a plausible lie. Retention trimming of the audit log is
  the same case: absence of evidence stays absence.
* **Keyset-paginated.** Bounded memory and bounded statement size on a user
  table of any size; rows that get filled drop out of the filter, and the
  ``pk__gt`` cursor only moves forward, so the walk cannot loop.
* **Irreversible in substance, no-op in form.** Backwards does nothing: once
  written, a backfilled stamp is indistinguishable from one the new code
  wrote, so "undo" would have to blank real data. Nothing downstream reads
  the column in a way a rollback breaks.
"""
from django.conf import settings
from django.db import migrations
from django.db.models import Max

#: Audit verbs that mean "this account successfully authenticated", frozen at
#: migration time (a migration must not follow later edits to AuthEventType).
#: The choke point writes ``login_success`` for every path and ``sso_login``
#: for SSO; the rest are verbs older releases wrote from the flow itself,
#: which is exactly the history this backfill exists to read.
SUCCESSFUL_LOGIN_EVENTS = (
    'login_success',
    'sso_login',
    'oauth_login',
    'qr_login',
    'totp_login',
    'passkey_login',
    'magic_link_used',
    'login_grant_used',
)

BATCH_SIZE = 1000


def backfill_last_login(apps, schema_editor):
    User = apps.get_model(settings.AUTH_USER_MODEL)
    AuthAuditLog = apps.get_model('authentication', 'AuthAuditLog')
    db = schema_editor.connection.alias

    cursor_pk = None
    while True:
        page = User.objects.using(db).filter(last_login__isnull=True)
        if cursor_pk is not None:
            page = page.filter(pk__gt=cursor_pk)
        pks = list(page.order_by('pk').values_list('pk', flat=True)[:BATCH_SIZE])
        if not pks:
            return
        cursor_pk = pks[-1]

        # .order_by() clears AuthAuditLog.Meta.ordering — a trailing ORDER BY
        # created_at would join the GROUP BY and give one row per event.
        latest = dict(
            AuthAuditLog.objects.using(db)
            .filter(user_id__in=pks, event_type__in=SUCCESSFUL_LOGIN_EVENTS)
            .order_by()
            .values_list('user_id')
            .annotate(when=Max('created_at'))
        )
        if not latest:
            continue

        rows = list(User.objects.using(db).filter(pk__in=list(latest)))
        for row in rows:
            row.last_login = latest[row.pk]
        User.objects.using(db).bulk_update(
            rows, ['last_login'], batch_size=BATCH_SIZE
        )


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('authentication', '0019_drop_verification_tables'),
    ]

    operations = [
        migrations.RunPython(backfill_last_login, migrations.RunPython.noop),
    ]
