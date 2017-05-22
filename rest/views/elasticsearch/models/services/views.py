# -*- coding: utf-8 -*-
from __future__ import absolute_import

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
