# -*- coding: utf-8 -*-
# Generated by Django 1.9.6 on 2016-07-19 22:19
from __future__ import unicode_literals

import datetime
from django.db import migrations, models
from django.utils.timezone import utc


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0008_auto_20160715_1321'),
    ]

    operations = [
        migrations.AddField(
            model_name='serviceaccount',
            name='active',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='serviceaccount',
            name='authorized_date',
            field=models.DateTimeField(auto_now=True, default=datetime.datetime(2016, 7, 19, 22, 19, 14, 81643, tzinfo=utc)),
            preserve_default=False,
        ),
    ]
