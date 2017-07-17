# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models

from .base import BaseWsModel


class Receipt(BaseWsModel):
    """
    This is a class for representing a receipt for a payment.
    """

    # Columns

    charge_id = models.CharField(max_length=32, null=False)
    charge_amount = models.IntegerField(null=False)
    charge_currency = models.CharField(max_length=16, null=False)
    description = models.CharField(max_length=256)

    # Foreign Keys

    order = models.OneToOneField(
        "rest.Order",
        related_name="receipt",
        null=True,
    )

    def __repr__(self):
        return "<%s - %s %s %s (%s)>" % (
            self.__class__.__name__,
            self.charge_id,
            self.charge_amount,
            self.charge_currency,
            self.uuid,
        )
