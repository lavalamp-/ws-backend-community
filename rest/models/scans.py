# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models

from .organizations import Organization
from .base import BaseWsModel


class ScanInvocation(BaseWsModel):
    """
    This is a class for representing when a user has invoked a scan of a given organization.
    """

    # Columns

    # Foreign Keys

    organization = models.ForeignKey(
        Organization,
        related_name="scan_invocations",
        null=True,
        on_delete=models.CASCADE,
    )
