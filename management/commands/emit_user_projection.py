"""Re-announce existing users as ``user.created`` (the projection backfill).

The observer in :mod:`stapel_auth.user_projection` only sees writes that
happen after it is installed. Every account that existed before this release
is therefore unknown to a consumer's shadow table, and a chat thread naming
one of them fails exactly the way it did before the fix. Run this once, in
the identity owner, after the consumers are deployed and listening:

    python manage.py emit_user_projection

Also the repair for a ``QuerySet.update()`` — the one write model signals
cannot see. ``--since`` narrows the replay to accounts touched recently
(``last_login``/``date_joined`` are not what changed, so it filters on
``date_joined``; use it for a fresh-accounts top-up, not as a correctness
tool). ``--dry-run`` counts without emitting.
"""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Emit user.created for existing users so consumers can backfill shadow rows."

    def add_arguments(self, parser):
        parser.add_argument(
            "--since",
            default=None,
            help="Only users with date_joined >= this ISO-8601 instant.",
        )
        parser.add_argument(
            "--batch-size", type=int, default=500,
            help="Rows fetched per query while iterating (default 500).",
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Report how many users would be announced; emit nothing.",
        )

    def handle(self, *args, **options):
        from django.contrib.auth import get_user_model
        from django.utils.dateparse import parse_datetime

        from stapel_auth.user_projection import replay

        qs = get_user_model()._default_manager.all().order_by("date_joined")
        since = options["since"]
        if since:
            moment = parse_datetime(since)
            if moment is None:
                self.stderr.write(f"--since: not an ISO-8601 datetime: {since!r}")
                return
            qs = qs.filter(date_joined__gte=moment)

        if options["dry_run"]:
            self.stdout.write(f"{qs.count()} user(s) would be announced (dry run)")
            return

        count = replay(qs, batch_size=options["batch_size"])
        self.stdout.write(self.style.SUCCESS(f"announced {count} user(s) as user.created"))
