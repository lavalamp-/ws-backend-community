# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models

from .services import NetworkService
from .base import BaseWsModel


class WebService(BaseWsModel):
    """
    This is a class for representing a web service found within a network service.
    """

    # Columns

    ip_address = models.CharField(max_length=128)
    port = models.IntegerField()
    host_name = models.CharField(max_length=128)
    ssl_enabled = models.NullBooleanField(default=False)
    scanning_status = models.BooleanField(default=False)

    # Foreign Keys

    network_service = models.ForeignKey(
        NetworkService,
        related_name="web_services",
        null=True,
        on_delete=models.CASCADE,
    )

    # Class Meta

    class Meta:
        unique_together = (
            ("host_name", "network_service", "ssl_enabled")
        )

    # Properties

    @property
    def last_completed_scan(self):
        """
        Get the last WebServiceScan owned by this WebService that was completed.
        :return: the last WebServiceScan owned by this WebService that was completed.
        """
        return self.web_service_scans.exclude(ended_at__isnull=True).order_by("-ended_at").first()

    @property
    def last_completed_scan_uuid(self):
        """
        Get the UUID of the last completed web service scan for this web service.
        :return: the UUID of the last completed web service scan for this web service.
        """
        last_completed_scan = self.last_completed_scan
        return last_completed_scan.uuid if last_completed_scan is not None else None


class WebServiceScan(BaseWsModel):
    """
    This is a class for representing a single scan of a given web service.
    """

    # Columns

    started_at = models.DateTimeField(null=False)
    ended_at = models.DateTimeField(null=True)

    # Foreign Keys

    web_service = models.ForeignKey(
        WebService,
        related_name="web_service_scans",
        null=True,
        on_delete=models.CASCADE,
    )


class WebServiceReport(BaseWsModel):
    """
    This is a class for representing the results of a single web service scan and the various technologies
    that were discovered on the scanned web service.
    """

    # Columns

    uses_wordpress = models.BooleanField(default=False)
    uses_iis = models.BooleanField(default=False)
    uses_apache = models.BooleanField(default=False)
    uses_nginx = models.BooleanField(default=False)

    # Foreign Keys

    web_service = models.OneToOneField(
        WebService,
        on_delete=models.CASCADE,
        null=False,
        related_name="web_service_report",
    )

    # Class Meta

    class Meta:
        unique_together = (
            ("web_service",)
        )
