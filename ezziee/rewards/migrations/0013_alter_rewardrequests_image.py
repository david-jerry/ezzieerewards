# Generated by Django 4.2.8 on 2024-01-15 15:44

from django.db import migrations, models
import ezziee.utils.files
import ezziee.utils.validators


class Migration(migrations.Migration):
    dependencies = [
        ("rewards", "0012_rewardactions_endpoint_alter_rewardactions_action_and_more"),
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