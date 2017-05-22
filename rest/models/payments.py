# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models

from .base import BaseWsModel
from .wsuser import WsUser
from lib import WsStripeHelper


class PaymentTokenManager(models.Manager):
    """
    This is a manager class for handling operations around the creation of PaymentToken models.
    """

    def create(self, **kwargs):
        token = super(PaymentTokenManager, self).create(**kwargs)
        if token.token_type == "stripe":
            WsStripeHelper.create_stripe_user_from_token(token)
        return token


class PaymentToken(BaseWsModel):
    """
    This is a class for representing a payment token.
    """

    # Management

    objects = PaymentTokenManager()

    # Columns

    name = models.CharField(max_length=32, null=True)
    token_type = models.CharField(max_length=16, default="stripe", null=False)
    token_value = models.CharField(max_length=64, null=False)
    card_type = models.CharField(max_length=32, null=True)
    expiration_month = models.IntegerField(null=False)
    expiration_year = models.IntegerField(null=False)
    card_last_four = models.CharField(max_length=4, null=False)
    can_be_charged = models.BooleanField(null=False, default=False)

    # Foreign Keys

    user = models.ForeignKey(
        WsUser,
        related_name="payment_tokens",
        on_delete=models.CASCADE,
    )

    def charge_token_for_amount(self, amount=None, currency="usd", description=None):
        """
        Charge this token for the specified amount of the specified currency and return a receipt for
        the charge.
        :param amount: The amount to charge.
        :param currency: A string depicting the currency to charge the token in.
        :param description: A description of what the charge is related to.
        :return: A payment receipt.
        """
        if self.token_type == "stripe":
            return WsStripeHelper.charge_token_for_amount(
                payment_token=self,
                amount=amount,
                currency=currency,
                description=description,
            )
        else:
            raise TypeError(
                "Unsure how to charge token of type %s."
                % (self.token_type,)
            )

    def __repr__(self):
        return "<%s - %s %s %s/%s %s (%s>" % (
            self.__class__.__name__,
            self.name,
            self.token_type,
            self.expiration_month,
            self.expiration_year,
            self.card_last_four,
            self.token_value,
        )


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

    payment_token = models.ForeignKey(
        PaymentToken,
        related_name="receipts",
        on_delete=models.CASCADE,
        null=True,
    )

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


class StripeCustomer(BaseWsModel):
    """
    This is a class for representing a Stripe customer.
    """

    # Columns

    customer_id = models.CharField(max_length=32, null=False)
    customer_email = models.EmailField(max_length=64, null=False)
    source = models.CharField(max_length=64, null=False)

    # Foreign Keys

    payment_token = models.OneToOneField(
        PaymentToken,
        related_name="stripe_customer",
        on_delete=models.CASCADE,
    )

    # Class Meta

    # Representation

    def __repr__(self):
        return "<%s - %s (%s)>" % (self.__class__.__name__, self.customer_email, self.customer_id)
