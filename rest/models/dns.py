# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models

from .base import BaseWsModel
from .organizations import Organization
from .networks import IpAddress
from .scans import ScanConfig


class DomainName(BaseWsModel):
    """
    This is a class for a domain name entered for a network.
    """

    # Columns

    name = models.CharField(max_length=256, help_text="The domain name.")
    is_monitored = models.BooleanField(default=False)
    scanning_enabled = models.BooleanField(
        default=True,
        help_text="Whether or not to include the domain name in scans.",
    )
    times_scanned = models.IntegerField(default=0)
    last_scan_time = models.DateTimeField(null=True)
    scanning_status = models.BooleanField(default=False)
    added_by = models.CharField(max_length=24, default="user", null=False)

    # Foreign Keys

    organization = models.ForeignKey(
        Organization,
        related_name="domain_names",
        on_delete=models.CASCADE,
        null=True,
        help_text="The organization that owns the domain.",
    )

    ip_addresses = models.ManyToManyField(
        IpAddress,
        related_name="domain_names",
    )

    # Class Meta

    class Meta:
        unique_together = (
            ("name", "organization"),
        )

    def __repr__(self):
        return "<%s - %s (%s>" % (self.__class__.__name__, self.name, self.uuid)


class DomainNameScan(BaseWsModel):
    """
    This is a class for representing information about the results of a domain name
    scan.
    """

    # Columns

    started_at = models.DateTimeField(null=False)
    ended_at = models.DateTimeField(null=True)

    # Foreign Keys

    domain_name = models.ForeignKey(
        DomainName,
        related_name="domain_name_scans",
        on_delete=models.CASCADE,
        null=False,
    )


class DnsRecordType(BaseWsModel):
    """
    This is a class for representing a DNS record type.
    """

    # Columns

    record_type = models.CharField(
        max_length=16,
        null=False,
        help_text="The DNS record type.",
    )

    # Foreign Keys

    scan_config = models.ForeignKey(
        ScanConfig,
        related_name="dns_record_types",
        on_delete=models.CASCADE,
        null=False,
    )

    def __repr__(self):
        return "<%s - %s (%s)>" % (
            self.__class__.__name__,
            self.uuid,
            self.record_type,
        )
