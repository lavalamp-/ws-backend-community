# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models

from .base import BaseWsModel
from .networks import Network, IpAddress
from .organizations import Organization


class NetworkService(BaseWsModel):
    """
    This is a class for a network service owned by an organization.
    """

    # Columns

    port = models.IntegerField()
    protocol = models.CharField(max_length=10)
    is_monitored = models.BooleanField(default=False)
    scanning_status = models.BooleanField(default=False)
    discovered_by = models.CharField(null=False, max_length=32, default="network scan")

    # Foreign Keys

    ip_address = models.ForeignKey(
        IpAddress,
        related_name="network_services",
        null=True,
        on_delete=models.CASCADE,
    )

    # Class Meta

    class Meta:
        unique_together = (
            ("ip_address", "port", "protocol"),
        )

    def __repr__(self):
        return "<%s - %s %s (%s)>" % (
            self.__class__.__name__,
            self.port,
            self.protocol,
            self.uuid,
        )


class NetworkServiceScan(BaseWsModel):
    """
    This is a class for representing a scan of a network service.
    """

    # Columns

    started_at = models.DateTimeField(null=False)
    ended_at = models.DateTimeField(null=True)

    # Foreign Keys

    network_service = models.ForeignKey(
        NetworkService,
        related_name="network_service_scans",
        null=True,
        on_delete=models.CASCADE,
    )


