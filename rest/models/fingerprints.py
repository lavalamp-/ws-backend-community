# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models

from .base import BaseWsModel


class HashFingerprint(BaseWsModel):
    """
    This is a model class for representing a SHA256 hash fingerprint.
    """

    # Columns

    hash = models.CharField(max_length=64)
    version = models.CharField(max_length=32)
    title = models.CharField(max_length=64)
    es_attribute = models.CharField(max_length=32)

    # Foreign Keys
