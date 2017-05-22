# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .esmixin import LatestDomainNameReportEsMixin
from .dbmixin import DomainNameDbMixin
from ..organizations import OrganizationDbMixin
from ..base import BaseElasticsearchManyMappedAPIView, BaseElasticsearchAnalyticsAPIView, \
    BaseElasticsearchSingleMappedAPIView, BaseElasticsearchRelatedAPIView


class OrganizationDomainNameReportListAPIView(
    LatestDomainNameReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView
):
    """
    This is an APIView class for retrieving all of the most recent domain name
    reports associated with a given organization.
    """


class OrganizationDomainNameReportAnalyticsAPIView(
    LatestDomainNameReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchAnalyticsAPIView,
):
    """
    This is an APIView class for retrieving analytical data about all of the domain
    name reports associated with an organization.
    """


class DomainNameReportDetailAPIView(
    LatestDomainNameReportEsMixin,
    DomainNameDbMixin,
    BaseElasticsearchSingleMappedAPIView,
):
    """
    This is an APIView class for retrieving details about the most recent
    domain name scan associated with a given domain name.
    """
