from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0027_usersignup'),
    ]

    operations = [
        migrations.AddField(
            model_name='signupattribution',
            name='landing_ref',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
    ]
