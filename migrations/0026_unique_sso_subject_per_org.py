"""The SSO identity gets the unique key it always needed.

``(org, sso_subject_id)`` — the IdP's NameID/sub inside one organisation — is
what a login actually asserts, and until now nothing stopped two rows from
claiming it. The first-login flow keyed on email instead, which is not unique
on the user model, so two concurrent first logins created two accounts for one
person and every later login raised ``MultipleObjectsReturned``.

Expand-only: the constraint is PARTIAL (blank subjects excluded), because a
membership created outside SSO carries no subject and "no identity" must not
read as one shared identity. Nothing is rewritten and no row is dropped.

The pre-check is the point of the forward step. A duplicate pair means two
accounts already answer to one IdP identity, and no migration can pick the
survivor — that is an account merge, a decision with a person behind it. So
this REFUSES, printing every colliding pair with its count and the rows
involved, rather than letting the AddConstraint fail with a bare
``UniqueViolation`` naming nothing, and rather than quietly deleting anything.
"""
from django.db import migrations, models


class DuplicateSSOIdentities(RuntimeError):
    """Two accounts answer to one (org, subject) pair — a human decides."""


def refuse_on_duplicate_identities(apps, schema_editor):
    OrgMembership = apps.get_model('authentication', 'OrgMembership')
    duplicates = (
        OrgMembership.objects
        .exclude(sso_subject_id='')
        .values('org_id', 'sso_subject_id')
        .annotate(rows=models.Count('id'))
        .filter(rows__gt=1)
        .order_by('-rows')
    )
    collisions = list(duplicates[:50])
    if not collisions:
        return

    total_pairs = duplicates.count()
    lines = []
    for entry in collisions:
        users = list(
            OrgMembership.objects
            .filter(org_id=entry['org_id'], sso_subject_id=entry['sso_subject_id'])
            .values_list('user_id', flat=True)
        )
        lines.append(
            f"  org={entry['org_id']} subject={entry['sso_subject_id']!r} "
            f"rows={entry['rows']} users={users}"
        )
    shown = "\n".join(lines)
    more = "" if total_pairs <= len(collisions) else (
        f"\n  … and {total_pairs - len(collisions)} more pairs"
    )
    raise DuplicateSSOIdentities(
        f"{total_pairs} (org, sso_subject_id) pair(s) are claimed by more than "
        f"one membership, so the identity cannot be made unique without "
        f"deciding which account survives — and that is an account merge, not "
        f"a schema change. Resolve them, then re-run this migration:\n"
        f"{shown}{more}"
    )


def noop(apps, schema_editor):
    """Reverse: the constraint goes, the data was never touched."""


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0025_widen_click_id_type'),
    ]

    operations = [
        migrations.RunPython(refuse_on_duplicate_identities, noop),
        migrations.AddConstraint(
            model_name='orgmembership',
            constraint=models.UniqueConstraint(
                condition=models.Q(('sso_subject_id', ''), _negated=True),
                fields=('org', 'sso_subject_id'),
                name='unique_sso_subject_per_org',
            ),
        ),
    ]
