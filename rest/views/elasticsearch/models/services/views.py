# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers

from lib import RegexLib
from .dbmixin import NetworkServiceDbMixin
from .esmixin import LatestSslSupportReportEsMixin, LatestSslSupportRelatedEsMixin
from ..organizations import OrganizationDbMixin
from ..base import BaseElasticsearchManyMappedAPIView, BaseElasticsearchAnalyticsAPIView, \
    BaseElasticsearchSingleMappedAPIView, BaseElasticsearchRelatedAPIView


class OrganizationSslSupportReportListAPIView(
    LatestSslSupportReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the SslSupportReport documents associated with the
    most recent network service scans for the given organization.
    """


class OrganizationSslSupportReportAnalyticsAPIView(
    LatestSslSupportReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchAnalyticsAPIView,
):
    """
    This is an APIView class for retrieving analytical data about all of the SslSupportReport documents
    associated with the most recent network service scans for the given organization.
    """


class SslSupportReportDetailAPIView(
    LatestSslSupportReportEsMixin,
    NetworkServiceDbMixin,
    BaseElasticsearchSingleMappedAPIView,
):
    """
    This is an APIView class for retrieving single details about a single SSL support instance.
    """


class NetworkServiceSslSupportRelatedAPIView(
    LatestSslSupportRelatedEsMixin,
    NetworkServiceDbMixin,
    BaseElasticsearchRelatedAPIView,
):
    """
    This is an APIView for retrieving details about Elasticsearch documents related to the SSL support
    associated with a network service.
    """


class SslSupportReportByIpListAPIView(
    LatestSslSupportReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView for retrieving all of the SSL support reports associated with an IP address.
    """

    def _validate_arguments(self):
        if not RegexLib.ipv4_address_regex.match(self.kwargs["ip"]):
            raise serializers.ValidationError("%s is not a valid IP address." % self.kwargs["ip"])

    def _apply_filters_to_query(self, query):
        query = super(SslSupportReportByIpListAPIView, self)._apply_filters_to_query(query)
        query.filter_by_ip_address(self.kwargs["ip"])
        return query


class SslSupportReportByDomainListAPIView(
    LatestSslSupportReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView for retrieving all of the SSL support reports associated with a domain name.
    """

    def _validate_arguments(self):
        if not RegexLib.domain_name_regex.match(self.kwargs["domain"]):
            raise serializers.ValidationError("%s is not a valid domain name." % self.kwargs["domain"])

    def _apply_filters_to_query(self, query):
        query = super(SslSupportReportByDomainListAPIView, self)._apply_filters_to_query(query)
        query.filter_by_domain(self.kwargs["domain"])
        return query
