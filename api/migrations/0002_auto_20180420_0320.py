# Generated by Django 2.0.4 on 2018-04-20 03:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='city',
            field=models.CharField(max_length=50, null=True),
        ),
    ]
