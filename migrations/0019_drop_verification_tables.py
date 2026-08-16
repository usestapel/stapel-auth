# stapel: cutover-phase
# The OTP tables retire into the core TTL store (stapel_core.verification.codes
# — see CHANGELOG for why a plaintext row was a defect, not a design).
# Deletion-driven: the code stops using them and they die in one release, which
# this fleet's stop-the-world deploy allows.
#
# Nothing is carried anywhere, and that is the point rather than an oversight.
# Every row is a one-time code with a ten-minute life, so the set worth moving
# is empty before any deploy finishes, and the store that replaces these tables
# refuses to hold a code in readable form on purpose — there is no destination.
# What the step below does instead is destroy: the rows are live bearer
# credentials in the clear, so they are erased BEFORE the DDL, and no path
# through this migration — including a rollback taken between the two
# operations — leaves a working code behind in a table nothing reads anymore.
from django.db import migrations


def purge_pending_codes(apps, schema_editor):
    """Erase the credentials, then let the DDL take the empty tables."""
    apps.get_model("authentication", "PhoneVerification").objects.all().delete()
    apps.get_model("authentication", "EmailVerification").objects.all().delete()


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0018_alter_emailverification_code_and_more'),
    ]

    operations = [
        # Erase first, drop second. Backwards is a no-op: the tables come back
        # empty, which is the only honest reverse for destroyed credentials.
        migrations.RunPython(purge_pending_codes, migrations.RunPython.noop),
        migrations.DeleteModel(name='PhoneVerification'),
        migrations.DeleteModel(name='EmailVerification'),
    ]
