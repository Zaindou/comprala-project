# Generated by Django 4.2.1 on 2023-06-08 22:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='passwordresettoken',
            name='token',
            field=models.CharField(default='XsontFljNrBcJRoQmSodM1', max_length=255, unique=True),
        ),
    ]
