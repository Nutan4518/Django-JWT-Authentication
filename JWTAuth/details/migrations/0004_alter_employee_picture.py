# Generated by Django 4.2.4 on 2023-08-26 06:41

import details.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('details', '0003_remove_employee_photo'),
    ]

    operations = [
        migrations.AlterField(
            model_name='employee',
            name='picture',
            field=models.ImageField(blank=True, upload_to=details.models.Employee.nameFile),
        ),
    ]
