# -*- coding: utf-8 -*-
from __future__ import absolute_import

import stripe

from .config import ConfigManager

config = ConfigManager.instance()


class WsStripeHelper(object):
    """
    This is a helper class for interacting with the Stripe API.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def charge_token_for_amount(payment_token=None, amount=None, currency="usd", description=None):
        """
        Charge the given token for the given amount in the given currency and associate the given
        description with the payment.
        :param payment_token: The token to charge.
        :param amount: The amount to charge.
        :param currency: A string depicting the currency that the charge should be made in.
        :param description: A description for the charge.
        :return:
        """
        api = WsStripeHelper.get_stripe_api()
        charge = api.Charge.create(
            amount=amount,
            currency=currency,
            description=description,
            customer=payment_token.stripe_customer.customer_id,
        )
        return payment_token.receipts.create(
            charge_id=charge["id"],
            charge_amount=charge["amount"],
            charge_currency=charge["currency"],
            description=description,
        )

    @staticmethod
    def create_stripe_user_from_token(payment_token):
        """
        Process the contents of the given payment token and create a Stripe user.
        :param payment_token: The payment token to process.
        :return: A new Stripe user object.
        """
        import rest.models
        api = WsStripeHelper.get_stripe_api()
        customer = api.Customer.create(
            email=payment_token.user.email,
            source=payment_token.token_value,
        )
        new_customer = rest.models.StripeCustomer.objects.create(
            customer_id=customer["id"],
            customer_email=customer["email"],
            source=customer["default_source"],
            payment_token=payment_token,
        )
        new_customer.save()
        payment_token.can_be_charged = True
        payment_token.save()
        return new_customer

    @staticmethod
    def get_stripe_api():
        """
        Get a Stripe API connector configured with our secret key.
        :return: A Stripe API connector configured with our secret key.
        """
        stripe.api_key = config.payments_stripe_secret_key
        return stripe

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
