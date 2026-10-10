import django.core.validators
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Release",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("version", models.CharField(
                    max_length=20, unique=True,
                    validators=[django.core.validators.RegexValidator(
                        r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.]+)?\Z",
                        "Use a version like 1.2.0.")])),
                ("released_at", models.DateTimeField(
                    default=django.utils.timezone.now)),
                ("notes", models.TextField(blank=True)),
                ("package", models.FileField(upload_to="releases/")),
                ("sha256", models.CharField(blank=True, editable=False,
                                            max_length=64)),
                ("size_bytes", models.PositiveBigIntegerField(
                    default=0, editable=False)),
                ("is_current", models.BooleanField(default=False)),
                ("download_count", models.PositiveIntegerField(
                    default=0, editable=False)),
            ],
            options={"ordering": ["-released_at", "-id"]},
        ),
        migrations.CreateModel(
            name="Signature",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True,
                                           serialize=False, verbose_name="ID")),
                ("sha256", models.CharField(
                    max_length=64, unique=True,
                    validators=[django.core.validators.RegexValidator(
                        "^[0-9a-fA-F]{64}$",
                        "Enter a 64-character SHA-256 hex digest.")])),
                ("name", models.CharField(max_length=120)),
                ("notes", models.TextField(blank=True)),
                ("active", models.BooleanField(default=True)),
                ("added_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={"ordering": ["name"]},
        ),
    ]
