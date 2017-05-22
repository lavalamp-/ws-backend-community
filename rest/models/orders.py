# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
from django.db import models
from django.db.models import F
from django.db.models import Sum
from django.utils import timezone

from .base import BaseWsModel
from .payments import Receipt

logger = logging.getLogger(__name__)


class OrderTier(BaseWsModel):
    """
    This is a class for representing a tier for order sizes.
    """

    # Columns

    number = models.IntegerField(null=False)
    name = models.CharField(max_length=32, null=False)
    max_domains = models.IntegerField(null=False)
    max_endpoints = models.IntegerField(null=False)
    price = models.IntegerField(null=False)


class OrderManager(models.Manager):
    """
    This is a manager class for handling operations around the creation of order models.
    """

    def create_from_token_user_and_organization(self, payment_token=None, organization=None, user=None):
        """
        Create and return a new order object based on the contents of the given payment token, organization,
        and user.
        :param payment_token: The payment token to populate the order with.
        :param organization: The organization to populate the order with.
        :param user: The user to populate the order with.
        :return: The newly-created Order.
        """
        order_tier = organization.current_order_tier
        to_return = self.create(
            user_email=user.email,
            order_tier_name=order_tier.name,
            order_tier_price=order_tier.price,
            scoped_domains_count=organization.monitored_domains_count,
            scoped_endpoints_count=organization.monitored_networks_count,
            scoped_endpoints_size=organization.monitored_networks_size,
            payment_token_type=payment_token.token_type,
            payment_token_value=payment_token.token_value,
            price_currency="usd",
            order_cost=organization.current_order_price,
            has_been_charged=False,
            user=user,
            organization=organization,
            payment_token=payment_token,
            payment_last_four=payment_token.card_last_four,
            payment_exp_month=payment_token.expiration_month,
            payment_exp_year=payment_token.expiration_year,
            is_enterprise_order=user.is_enterprise_user,
        )
        for network in organization.monitored_networks:
            to_return.networks.create(network=network)
        for domain_name in organization.monitored_domains:
            to_return.domain_names.create(domain_name=domain_name)
        return to_return

    def create_from_user_and_organization(self, user=None, organization=None):
        """
        Create and return a new order object based on the contents of the given organization and user.
        :param user: The user to populate data from.
        :param organization: The organization to populate data from.
        :return: The newly-created order.
        """
        order_tier = organization.current_order_tier
        to_return = self.create(
            user_email=user.email,
            order_tier_name=order_tier.name,
            order_tier_price=order_tier.price,
            scoped_domains_count=organization.monitored_domains_count,
            scoped_endpoints_count=organization.monitored_networks_count,
            scoped_endpoints_size=organization.monitored_networks_size,
            price_currency="usd",
            order_cost=organization.current_order_price,
            has_been_charged=False,
            user=user,
            organization=organization,
            is_enterprise_order=user.is_enterprise_user,
        )
        for network in organization.monitored_networks:
            to_return.networks.create(network=network)
        for domain_name in organization.monitored_domains:
            to_return.domain_names.create(domain_name=domain_name)
        return to_return


class Order(BaseWsModel):
    """
    This is a class for representing an order.
    """

    # Management

    objects = OrderManager()

    # Columns

    started_at = models.DateTimeField(null=True)
    completed_at = models.DateTimeField(null=True)
    user_email = models.EmailField(null=False)
    order_tier_name = models.CharField(max_length=32, null=False)
    order_tier_price = models.IntegerField(null=False)
    scoped_domains_count = models.IntegerField(null=False)
    scoped_endpoints_count = models.IntegerField(null=False)
    scoped_endpoints_size = models.IntegerField(null=False)
    payment_token_type = models.CharField(max_length=16, null=True)
    payment_token_value = models.CharField(max_length=64, null=True)
    price_currency = models.CharField(max_length=16, default="usd")
    order_cost = models.IntegerField(null=False)
    charge_amount = models.IntegerField(null=True)
    transaction_id = models.CharField(max_length=32)
    has_been_charged = models.BooleanField(null=False, default=False)
    charged_at = models.DateTimeField(null=True)
    payment_last_four = models.CharField(max_length=4, null=True)
    payment_exp_month = models.IntegerField(null=True)
    payment_exp_year = models.IntegerField(null=True)
    is_enterprise_order = models.BooleanField(null=False, default=False)

    # Foreign Keys

    user = models.ForeignKey(
        "rest.WsUser",
        related_name="orders",
    )

    organization = models.ForeignKey(
        "rest.Organization",
        related_name="orders",
    )

    payment_token = models.ForeignKey(
        "rest.PaymentToken",
        related_name="orders",
        null=True,
    )

    # Methods

    def get_receipt_description(self):
        """
        Get a string describing this order for the purposes of displaying receipt information
        for end users.
        :return: A string describing this order for the purposes of displaying receipt information
        for end users.
        """
        separator = "----------------------------------------------------------------------------------------------------"
        separator_len = len(separator)
        to_return = []
        to_return.append(separator)
        to_return.append("Receipt for order %s" % (self.uuid,))
        to_return.append(separator)
        to_return.append("Scoped Endpoints")
        to_return.append("")
        to_return.append("Networks x%s (%s endpoints total)" % (self.scoped_endpoints_count, self.scoped_endpoints_size))
        to_return.append("Domain Names x%s" % (self.scoped_domains_count,))
        to_return.append(separator)
        to_return.append("Pricing")
        to_return.append("")
        to_return.append("Pricing Tier: %s" % (self.order_tier_name,))
        to_return.append("Price For Tier: $%s" % (self.order_tier_price / 100.0,))
        to_return.append(separator)
        to_return.append("Discounts")
        to_return.append("")
        if self.order_discounts.count() == 0:
            to_return.append("No Discounts Applied")
        else:
            for order_discount in self.order_discounts.all():
                to_return.append("%s: -$%s" % (order_discount.description, order_discount.amount / 100.0))
            to_return.append("")
            to_return.append("Total of $%s Discounted" % (self.discount_amount / 100.0,))
            to_return.append("Price After Discounts: $%s" % (self.price_after_discount / 100.0,))
        to_return.append(separator)
        if self.user.is_enterprise_user:
            to_return.append("No Payment Required (Enterprise User)")
        else:
            to_return.append("Payment Method: ****-****-****-%s (expires %s/%s)" % (
                self.payment_last_four,
                self.payment_exp_month,
                self.payment_exp_year,
            ))
            to_return.append("Amount Charged: $%s" % (self.charge_amount / 100.0,))
            to_return.append("Charged At: %s" % (self.charged_at,))
        to_return.append(separator)
        return "\n".join([x.rjust(separator_len) for x in to_return])

    def place_order(self):
        """
        Place this order.
        :return: True if the order was placed successfully, False otherwise.
        """
        if self.has_been_charged:
            raise ValueError("This order has already been placed/charged.")
        try:
            from .payments import Receipt
            if not self.user.is_enterprise_user:
                receipt = self.payment_token.charge_token_for_amount(
                    amount=self.price_after_discount,
                    currency=self.price_currency,
                    description="Charge for order %s" % (self.uuid,)
                )
            else:
                receipt = Receipt.objects.create(
                    charge_id="ENTERPRISE RECEIPT",
                    charge_amount=0,
                    charge_currency="usd",
                    description="Charge for order %s" % (self.uuid,)
                )
            self.receipt = receipt
            self.has_been_charged = True
            self.charged_at = timezone.now()
            self.charge_amount = self.price_after_discount
            self.organization.update_monitored_times_scanned()
            return True
        except Exception as e:
            logger.error(
                "Exception thrown when placing order (%s): %s."
                % (e.__class__.__name__, e.message)
            )
            return False

    # Properties

    @property
    def discount_amount(self):
        """
        Get the total amount that this order should be discounted.
        :return: A number representing the total amount that this order should be discounted.
        """
        if self.order_discounts.count() == 0:
            return 0
        else:
            return self.order_discounts.aggregate(Sum("amount"))["amount__sum"]

    @property
    def price_after_discount(self):
        """
        Get the total amount that this order costs after discounts.
        :return: the total amount that this order costs after discounts.
        """
        if self.user.is_enterprise_user:
            return 0
        else:
            return max(self.order_cost - self.discount_amount, 0)

    # Representation

    def __repr__(self):
        return "<%s - Order for %s (%s) (%s)>" % (
            self.__class__.__name__,
            self.user_email,
            "charged" if self.has_been_charged else "not charged",
            self.uuid,
        )


class OrderDiscount(BaseWsModel):
    """
    This is a class for representing a discount applied to an order.
    """

    # Columns

    amount = models.IntegerField(null=False)
    name = models.CharField(max_length=32, null=False)
    description = models.CharField(max_length=128)

    # Foreign Keys

    order = models.ForeignKey(
        "rest.Order",
        related_name="order_discounts",
        on_delete=models.CASCADE,
    )

    # Representation

    def __repr__(self):
        return "<%s - %s %s (%s)>" % (
            self.__class__.__name__,
            self.name,
            self.amount,
            self.uuid,
        )


class OrderNetwork(BaseWsModel):
    """
    This is a class for representing a network that is associated with an order.
    """

    # Columns

    network_cidr = models.CharField(max_length=32, null=False)

    # Methods

    def save(self, *args, **kwargs):
        self.network_cidr = self.network.cidr_range
        return super(OrderNetwork, self).save(*args, **kwargs)

    # Foreign Keys

    order = models.ForeignKey(
        "rest.Order",
        related_name="networks",
        on_delete=models.CASCADE,
    )

    network = models.ForeignKey(
        "rest.Network",
        related_name="order_networks",
    )


class OrderDomainName(BaseWsModel):
    """
    This is a class for representing a domain name that is associated with an order.
    """

    # Columns

    name = models.CharField(max_length=256, null=False)

    # Methods

    def save(self, *args, **kwargs):
        self.name = self.domain_name.name
        return super(OrderDomainName, self).save(*args, **kwargs)

    # Foreign Keys

    order = models.ForeignKey(
        "rest.Order",
        related_name="domain_names",
        on_delete=models.CASCADE,
    )

    domain_name = models.ForeignKey(
        "rest.DomainName",
        related_name="order_domain_names",
    )
