# Generated by Django 5.1.7 on 2025-04-16 02:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('logIn', '0007_lockoutlog'),
    ]

    operations = [
        migrations.AddField(
            model_name='lockoutlog',
            name='is_simulation',
            field=models.BooleanField(default=False),
        ),
    ]
