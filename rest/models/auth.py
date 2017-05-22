# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.conf import settings
from django.db import models

from .base import BaseWsModel
from .organizations import Organization


class WsAuthGroup(BaseWsModel):
    """
    This is a class for representing authorization groups specific to the Web Sight platform.
    """

    # Columns

    name = models.CharField(max_length=64)

    users = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="auth_groups",
    )

    organization = models.ForeignKey(
        Organization,
        related_name="auth_groups",
        null=True,
    )

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
