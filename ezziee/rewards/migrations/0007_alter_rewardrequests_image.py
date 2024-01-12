# Generated by Django 4.2.8 on 2023-12-26 01:45

from django.db import migrations, models
import ezziee.utils.files
import ezziee.utils.validators


class Migration(migrations.Migration):
    dependencies = [
        ("rewards", "0006_remove_rewardactions_subscribers_and_more"),
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
    ]
