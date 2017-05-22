# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models

from .base import BaseConfig


class ZmapConfig(BaseConfig):
    """
    This is a class for representing configuration details for running Zmap.
    """

    # Columns

    bandwidth = models.CharField(max_length=16)

    # Foreign Keys


class NmapConfig(BaseConfig):
    """
    This is a class for representing configuration details for running Nmap.
    """

    # Columns

    speed = models.IntegerField(null=False)
    output_type = models.CharField(null=False, max_length=16)
    fingerprinting_enabled = models.BooleanField(null=False)
    resolution_enabled = models.BooleanField(null=False)
    host_discovery_enabled = models.BooleanField(null=False)

    # Foreign Keys
