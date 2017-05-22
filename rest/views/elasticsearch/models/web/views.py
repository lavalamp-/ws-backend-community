# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseElasticsearchSingleMappedAPIView, BaseElasticsearchAnalyticsAPIView, \
    BaseElasticsearchManyMappedAPIView
from .esmixin import LatestWebTechnologiesReportEsMixin, LatestHttpTransactionEsMixin, \
    LatestHttpScreenshotEsMixin, LatestWebServiceReportEsMixin, LatestWebResourceEsMixin
from .dbmixin import WebServiceDbMixin
from ..organizations import OrganizationDbMixin


class OrganizationWebTechReportAnalyticsAPIView(
    LatestWebTechnologiesReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchAnalyticsAPIView,
):
    """
    This is an APIView class for retrieving analytics data about all of the web technology reports
    associated with the most recent web service scans for an organization.
    """


class OrganizationWebTechReportListAPIView(
    LatestWebTechnologiesReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the web technology reports for an organization.
    """


class OrganizationWebTransactionAnalyticsAPIView(
    LatestHttpTransactionEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchAnalyticsAPIView,
):
    """
    This is an APIView class for retrieving analytical data about all of the HTTP transactions associated
    with the most recent web service scans for an organization.
    """

    def _get_content_length_interval(self):
        return 40000


class OrganizationWebTransactionListAPIView(
    LatestHttpTransactionEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the HTTP transactions associated with the most recent
    web service scans for the given organization.
    """


class OrganizationWebScreenshotsListAPIView(
    LatestHttpScreenshotEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the HTTP screenshots associated with the most recent
    web service scans for the given organization.
    """


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


class WebServiceHttpTransactionListAPIView(
    LatestHttpTransactionEsMixin,
    WebServiceDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving all of the HTTP transactions associated with the most recent scan
    for a given web service.
    """


class WebServiceHttpTransactionAnalyticsAPIView(
    LatestHttpTransactionEsMixin,
    WebServiceDbMixin,
    BaseElasticsearchAnalyticsAPIView,
):
    """
    This is an APIView class for retrieving analytical data about the HTTP transactions associated with the
    most recent scan for a given web service.
    """

    def _get_content_length_interval(self):
        return 40000


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
