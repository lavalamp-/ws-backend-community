# -*- coding: utf-8 -*-
from __future__ import absolute_import

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
