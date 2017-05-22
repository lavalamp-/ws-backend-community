# -*- coding: utf-8 -*-
from __future__ import absolute_import
from django.db import models

import uuid


class BaseWsModel(models.Model):
    """
    This is a base model class for all model classes used by the Web Sight back-end.
    """

    # Columns

    uuid = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created = models.DateTimeField(auto_now_add=True)

    # Foreign Keys

    class Meta:
        ordering = ('created',)
        abstract = True


class BaseConfig(BaseWsModel):
    """
    This is a base class for representing configuration settings for other model objects.
    """

    # Columns

    name = models.CharField(max_length=32)

    # Foreign Keys

    class Meta:
        abstract = True


class BaseDomainName(BaseWsModel):
    """
    This is a base class for representing a domain name.
    """

    # Columns

    name = models.CharField(max_length=256)

    # Foreign Keys

    class Meta:
        abstract = True


class BaseIpAddress(BaseWsModel):
    """
    This is a class for representing an IP address.
    """

    # Columns

    address = models.CharField(max_length=64)
    address_type = models.IntegerField()

    # Foreign Keys

    class Meta:
        abstract = True


class BaseNetwork(BaseWsModel):
    """
    This is a base class for representing network ranges.
    """

    # Columns

    address = models.CharField(max_length=64)
    mask_length = models.IntegerField()
    name = models.CharField(max_length=32)

    class Meta:
        abstract = True
