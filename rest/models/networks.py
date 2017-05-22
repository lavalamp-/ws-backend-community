# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models

from .organizations import Organization
from .base import BaseWsModel


class Network(BaseWsModel):
    """
    This is a class for representing a network range that an organization knows about.
    """

    # Columns

    address = models.CharField(max_length=64)
    mask_length = models.IntegerField()
    name = models.CharField(max_length=32)
    scanning_enabled = models.BooleanField(default=True)
    endpoint_count = models.IntegerField(default=0)
    cidr_range = models.CharField(max_length=64)
    added_by = models.CharField(max_length=10, default="user", null=False)
    times_scanned = models.IntegerField(default=0)
    last_scan_time = models.DateTimeField(null=True)

    # Foreign Keys

    organization = models.ForeignKey(
        Organization,
        related_name="networks",
        null=True,
        on_delete=models.CASCADE,
    )

    # Class Meta

    class Meta:
        unique_together = (
            ("address", "mask_length", "organization"),
            ("name", "organization"),
            ("cidr_range", "organization"),
        )

    # Methods

    def save(self, *args, **kwargs):
        from lib.parsing import CidrRangeWrapper
        self.endpoint_count = pow(2, 32 - self.mask_length)
        cidr_wrapper = CidrRangeWrapper.from_cidr_range(address=self.address, mask_length=self.mask_length)
        self.cidr_range = cidr_wrapper.parsed_cidr_range
        self.address = cidr_wrapper.parsed_address
        return super(Network, self).save(*args, **kwargs)

    # Properties

    @property
    def monitored_network_service_count(self):
        """
        Get the number of network services associated with this network that are currently
        being monitored.
        :return: the number of network services associated with this network that are
        currently being monitored.
        """
        return self.ip_addresses\
            .filter(network_services__is_monitored=True)\
            .values("network_services__uuid")\
            .count()

    @property
    def network_service_count(self):
        """
        Get the number of network services associated with this network.
        :return: the number of network services associated with this network.
        """
        return self.ip_addresses.values("network_services__uuid").count()

    @property
    def unmonitored_network_service_count(self):
        """
        Get the number of network services associated with this network that are not currently
        being monitored.
        :return: the number of network services associated with this network that are not
        currently being monitored.
        """
        return self.ip_addresses \
            .filter(network_services__is_monitored=False) \
            .values("network_services__uuid") \
            .count()

    def __repr__(self):
        return "<%s - %s %s (%s)>" % (
            self.__class__.__name__,
            self.name,
            self.cidr_range,
            self.uuid,
        )


class IpAddress(BaseWsModel):
    """
    This is a class for an IP address collected by a scan.
    """

    # Columns

    address = models.CharField(max_length=64)
    address_type = models.CharField(max_length=10)
    is_monitored = models.BooleanField(default=False)
    scanning_status = models.BooleanField(default=False)

    # Foreign Keys

    network = models.ForeignKey(
        Network,
        related_name="ip_addresses",
        on_delete=models.CASCADE,
        null=True,
    )

    # Class Meta

    class Meta:
        unique_together = (
            ("network", "address", "address_type"),
        )
        
    # Properties

    @property
    def monitored_network_service_count(self):
        """
        Get the number of network services associated with this IP address that are currently
        being monitored.
        :return: the number of network services associated with this IP address that are currently
        being monitored.
        """
        return self.network_services.filter(is_monitored=True).count()

    @property
    def network_service_count(self):
        """
        Get the number of network services associated with this IP address.
        :return: the number of network services associated with this IP address.
        """
        return self.network_services.count()

    def __repr__(self):
        return "<%s - %s (%s)>" % (self.__class__.__name__, self.address, self.uuid)


class IpAddressScan(BaseWsModel):
    """
    This is a class for representing a scan of a single IP address.
    """

    # Columns

    started_at = models.DateTimeField(null=False)
    ended_at = models.DateTimeField(null=True)

    # Foreign Keys

    ip_address = models.ForeignKey(
        IpAddress,
        related_name="ip_address_scans",
        null=False,
        on_delete=models.CASCADE,
    )


class NetworkConfig(BaseWsModel):
    """
    This is a class for representing the scanning configuration for an organization network.
    """

    # Columns

    name = models.CharField(max_length=32)

    # Foreign Keys

    network = models.OneToOneField(
        Network,
        on_delete=models.CASCADE,
        related_name="network_config",
    )
