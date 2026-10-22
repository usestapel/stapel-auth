"""List accounts that share one mailbox up to letter case. Read-only.

Before stapel-auth 0.49 the OTP and password doors matched email exactly, so
``Alice@x.com`` and ``alice@x.com`` could become two accounts. Every door now
matches case-insensitively (``accounts.users_by_email``) and picks the oldest
row; this command is the input to a deduplication an operator decides on.
A unique constraint on ``lower(email)`` can only be added once it prints
nothing.
"""
import json

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db.models import Count
from django.db.models.functions import Lower


class Command(BaseCommand):
    help = "List accounts whose email differs only by letter case (no writes)."

    def add_arguments(self, parser):
        parser.add_argument("--json", action="store_true", help="Machine output")

    def handle(self, *args, **options):
        User = get_user_model()
        groups = (
            User.objects.exclude(email__isnull=True)
            .exclude(email="")
            .annotate(mailbox=Lower("email"))
            .values("mailbox")
            .annotate(n=Count("pk"))
            .filter(n__gt=1)
            .order_by("mailbox")
        )
        report = []
        for group in groups:
            rows = (
                User.objects.filter(email__iexact=group["mailbox"])
                .order_by("date_joined", "pk")
                .values("pk", "email", "date_joined", "is_email_verified", "is_active")
            )
            report.append({
                "mailbox": group["mailbox"],
                "accounts": [
                    {
                        "id": str(row["pk"]),
                        "email": row["email"],
                        "date_joined": row["date_joined"].isoformat() if row["date_joined"] else None,
                        "email_verified": row["is_email_verified"],
                        "active": row["is_active"],
                    }
                    for row in rows
                ],
            })
        if options["json"]:
            self.stdout.write(json.dumps(report, indent=2))
            return
        for group in report:
            self.stdout.write(f"{group['mailbox']}: {len(group['accounts'])} accounts")
            for acc in group["accounts"]:
                self.stdout.write(
                    f"  {acc['id']} {acc['email']} joined={acc['date_joined']} "
                    f"verified={acc['email_verified']} active={acc['active']}"
                )
        self.stdout.write(f"{len(report)} mailbox(es) with more than one account.")
