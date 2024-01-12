# Generated by Django 4.2.8 on 2023-12-26 01:47

from django.conf import settings
from django.db import migrations, models
import ezziee.utils.files
import ezziee.utils.validators


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("rewards", "0007_alter_rewardrequests_image"),
    ]

    operations = [
        migrations.AlterField(
            model_name="rewardrequests",
            name="image",
            field=models.FileField(
                blank=True,
                null=True,
                upload_to=ezziee.utils.files.FileUploader.profile_image_upload_path,
                validators=[ezziee.utils.validators.image_validate_file_extension],
            ),
        ),
        migrations.AlterField(
            model_name="rewardrequests",
            name="subscribers",
            field=models.ManyToManyField(
                blank=True, null=True, related_name="requests", to=settings.AUTH_USER_MODEL, verbose_name="subscribers"
            ),
        ),
    ]
