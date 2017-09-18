# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .esmixin import LatestIpAddressReportEsMixin
from .dbmixin import IpAddressDbMixin
from ..organizations import OrganizationDbMixin
from ..base import BaseElasticsearchManyMappedAPIView, BaseElasticsearchAnalyticsAPIView, \
    BaseElasticsearchSingleMappedAPIView


class OrganizationIpAddressReportListAPIView(
    LatestIpAddressReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the IpAddressReport documents associated with the
    most recent IP address scans for the given organization.
    """


class OrganizationIpAddressReportAnalyticsAPIView(
    LatestIpAddressReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchAnalyticsAPIView,
):
    """
    This is an APIView class for retrieving analytical data about all of the IpAddressReport documents
    associated with the most recent IP address scans for the given organization.
    """


class IpAddressReportDetailAPIView(
    LatestIpAddressReportEsMixin,
    IpAddressDbMixin,
    BaseElasticsearchSingleMappedAPIView,
):
    """
    This is an APIView class for retrieving analytical data about all of the IpAdressReport documents
    associated with the most recent IP address scan for a given IP address.
    """
