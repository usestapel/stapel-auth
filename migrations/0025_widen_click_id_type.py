"""Three more ad platforms, and a row that may carry campaign tags only.

State-only: ``choices`` and ``blank`` are Django-level validation, so this
migration emits no SQL on any backend — nothing to expand, nothing to
contract, and an old release reading the table sees exactly the columns it
already saw. What changes is what the application will now accept into
them: ``yclid``/``fbclid``/``ttclid`` beside the three Google identifiers,
and a blank pair on a landing that carried only ``utm_*``.

Widening only. No stored value stops being valid, so this runs forward on a
live table with no backfill and no window.
"""
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0024_signupattribution'),
    ]

    operations = [
        migrations.AlterField(
            model_name='signupattribution',
            name='click_id',
            field=models.CharField(blank=True, max_length=512),
        ),
        migrations.AlterField(
            model_name='signupattribution',
            name='click_id_type',
            field=models.CharField(
                blank=True,
                choices=[
                    ('gclid', 'gclid'),
                    ('gbraid', 'gbraid'),
                    ('wbraid', 'wbraid'),
                    ('yclid', 'yclid'),
                    ('fbclid', 'fbclid'),
                    ('ttclid', 'ttclid'),
                ],
                max_length=16,
            ),
        ),
    ]
