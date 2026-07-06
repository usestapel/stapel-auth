import uuid

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('authentication', '0012_alter_authauditlog_event_type_alter_orgmembership_id_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='StaffRoleAssignment',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('role_name', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('assigned_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='staff_roles_granted', to=settings.AUTH_USER_MODEL)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='staff_role_assignments', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'db_table': 'staff_role_assignments',
                'ordering': ['role_name'],
            },
        ),
        migrations.AddConstraint(
            model_name='staffroleassignment',
            constraint=models.UniqueConstraint(fields=('user', 'role_name'), name='unique_staff_role_per_user'),
        ),
    ]
