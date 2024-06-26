# Generated by Django 4.2.4 on 2023-08-31 12:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_tokenblacklistoutstandingtoken'),
    ]

    operations = [
        migrations.CreateModel(
            name='RefreshTokens',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('token', models.TextField()),
                ('jti', models.CharField(max_length=255)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('user_id', models.BigIntegerField()),
            ],
            options={
                'db_table': 'token_blacklist_blacklistedtoken',
                'managed': False,
            },
        ),
        migrations.DeleteModel(
            name='TokenBlacklistOutstandingToken',
        ),
    ]
