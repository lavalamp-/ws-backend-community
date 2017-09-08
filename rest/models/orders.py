# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
from django.db import models
from django.db.models import F
from django.db.models import Sum
from django.utils import timezone

from .base import BaseWsModel
from .payments import Receipt
import rest.models

logger = logging.getLogger(__name__)


class OrderManager(models.Manager):
    """
    This is a manager class for handling operations around the creation of order models.
    """

    def create(self, *args, **kwargs):
        """
        Create and return an instance of an order.
        :param args: Positional arguments for super.
        :param kwargs: Keyword arguments for super.
        :return: The newly-created order.
        """
        from .scans import ScanConfig
        to_return = super(OrderManager, self).create(*args, **kwargs)
        organization = kwargs.get("organization", None)
        user = kwargs.get("user", None)
        if organization:
            to_return.scan_config = organization.scan_config.duplicate()
            to_return.scan_config.user = user
            to_return.scan_config.save()
        else:
            to_return.scan_config = ScanConfig.objects.create(
                order=to_return,
                organization=organization,
                user=user,
            )
        return to_return

    def create_from_user_and_organization(self, user=None, organization=None):
        """
        Create and return a new order object based on the contents of the given organization and user.
        :param user: The user to populate data from.
        :param organization: The organization to populate data from.
        :return: The newly-created order.
        """
        to_return = self.create(
            user_email=user.email,
            scoped_domains_count=organization.monitored_domains_count,
            scoped_endpoints_count=organization.monitored_networks_count,
            scoped_endpoints_size=organization.monitored_networks_size,
            user=user,
            organization=organization,
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
    scoped_domains_count = models.IntegerField(null=False)
    scoped_endpoints_count = models.IntegerField(null=False)
    scoped_endpoints_size = models.IntegerField(null=False)
    has_been_placed = models.BooleanField(default=False)

    # Foreign Keys

    user = models.ForeignKey(
        "rest.WsUser",
        related_name="orders",
    )

    organization = models.ForeignKey(
        "rest.Organization",
        related_name="orders",
    )

    # Methods

    def get_ready_errors(self):
        """
        Get a list of strings describing errors associated with this Order object that prevent it
        from being used in a placed order.
        :return: A list of strings describing errors associated with this Order object that prevent it
        from being used in a placed order.
        """
        to_return = []
        try:
            to_return.extend(self.scan_config.get_ready_errors())
        except rest.models.ScanConfig.DoesNotExist:
            to_return.append("The order has no scanning configuration associated with it.")
        if self.has_been_placed:
            to_return.append("This order has already been placed.")
        if self.networks.count() == 0 and self.domain_names.count() == 0:
            to_return.append("No networks, IP addresses, or domain names were specified in the order.")
        return to_return

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
        return "\n".join([x.rjust(separator_len) for x in to_return])

    def place_order(self):
        """
        Place this order.
        :return: True if the order was placed successfully, False otherwise.
        """
        from .payments import Receipt
        receipt = Receipt.objects.create(
            charge_id="ENTERPRISE RECEIPT",
            charge_amount=0,
            charge_currency="usd",
            description="Charge for order %s" % (self.uuid,)
        )
        self.receipt = receipt
        self.organization.update_monitored_times_scanned()
        self.has_been_placed = True
        return True

    # Properties

    @property
    def is_ready_to_place(self):
        """
        Get a boolean depicting whether or not this order is ready to be placed.
        :return: A boolean depicting whether or not this order is ready to be placed.
        """
        return len(self.get_ready_errors()) == 0

    # Representation

    def __repr__(self):
        return "<%s - Order for %s (%s)>" % (
            self.__class__.__name__,
            self.user_email,
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
