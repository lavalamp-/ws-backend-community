# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers

from lib import RegexLib
from ..base import BaseElasticsearchSingleMappedAPIView, BaseElasticsearchAnalyticsAPIView, \
    BaseElasticsearchManyMappedAPIView
from .esmixin import LatestWebTechnologiesReportEsMixin, LatestHttpTransactionEsMixin, \
    LatestHttpScreenshotEsMixin, LatestWebServiceReportEsMixin, LatestWebResourceEsMixin
from .dbmixin import WebServiceDbMixin
from ..organizations import OrganizationDbMixin


class OrganizationWebServiceReportListAPIView(
    LatestWebServiceReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the WebServiceReport documents associated with the most
    web service scans for the given organization.
    """


class OrganizationWebServiceReportAnalyticsAPIView(
    LatestWebServiceReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchAnalyticsAPIView,
):
    """
    This is an APIView class for retrieving analytical data about all of the web service reports associated
    with the most recent web service scans for an organization.
    """


class WebServiceReportDetailAPIView(
    LatestWebServiceReportEsMixin,
    WebServiceDbMixin,
    BaseElasticsearchSingleMappedAPIView,
):
    """
    This is an APIView class for retrieving a single WebServiceReport document pertaining to the most recent
    scan for a given web service.
    """


class WebServiceReportByIpAddressListAPIView(
    LatestWebServiceReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the latest WebServiceReport documents associated with an
    IP address.
    """

    def _validate_arguments(self):
        if not RegexLib.ipv4_address_regex.match(self.kwargs["ip"]):
            raise serializers.ValidationError("%s is not a valid IP address." % self.kwargs["ip"])

    def _apply_filters_to_query(self, query):
        query = super(WebServiceReportByIpAddressListAPIView, self)._apply_aggregates_to_query(query)
        query.filter_by_ip_address(self.kwargs["ip"])
        return query


class WebServiceReportByDomainListAPIView(
    LatestWebServiceReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the latest WebServiceReport documents associated with a
    domain name.
    """

    def _validate_arguments(self):
        if not RegexLib.domain_name_regex.match(self.kwargs["domain"]):
            raise serializers.ValidationError("%s is not a valid domain name." % self.kwargs["domain"])

    def _apply_filters_to_query(self, query):
        query = super(WebServiceReportByDomainListAPIView, self)._apply_aggregates_to_query(query)
        query.filter_by_web_service_host_name(self.kwargs["domain"])
        return query


class WebServiceScreenshotListAPIView(
    LatestHttpScreenshotEsMixin,
    WebServiceDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the HTTP screenshots associated with a given web service from
    the most recent web service scan.
    """


class WebServiceResourceListAPIView(
    LatestWebResourceEsMixin,
    WebServiceDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the web resources discovered during a given web service scan.
    """


class WebServiceResourceAnalyticsAPIView(
    LatestWebResourceEsMixin,
    WebServiceDbMixin,
    BaseElasticsearchAnalyticsAPIView,
):
    """
    This is an APIView class for retrieving analytical data about the web resources discovered during a given
    web service scan.
    """
