from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0008_add_device_type_details_to_session'),
    ]

    operations = [
        migrations.AddField(
            model_name='usersession',
            name='access_jti',
            field=models.CharField(max_length=64, blank=True, default='', db_index=True),
            preserve_default=False,
        ),
    ]
