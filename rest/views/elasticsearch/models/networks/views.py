# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers

from lib import RegexLib
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
    This is an APIView class for retrieving analytical data about all of the IpAddressReport documents
    associated with the most recent IP address scan for a given IP address.
    """


class IpAddressReportByIpDetailAPIView(
    LatestIpAddressReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchSingleMappedAPIView,
):
    """
    This is an APIView class for retrieving analyical data about a single IP address report document
    associated with a single IP address.
    """

    def _validate_arguments(self):
        if not RegexLib.ipv4_address_regex.match(self.kwargs["ip"]):
            raise serializers.ValidationError("%s is not a valid IP address." % self.kwargs["ip"])

    def _apply_filters_to_query(self, query):
        query = super(IpAddressReportByIpDetailAPIView, self)._apply_filters_to_query(query)
        query.filter_by_ip_address(self.kwargs["ip"])
        return query
