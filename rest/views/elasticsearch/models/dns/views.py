# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers

from lib import RegexLib
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


class DomainNameReportByDomainDetailAPIView(
    LatestDomainNameReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchSingleMappedAPIView,
):
    """
    This is an APIView class for retrieving the domain name report for a single
    domain name as found during its most recent domain name scan.
    """

    def _validate_arguments(self):
        if not RegexLib.domain_name_regex.match(self.kwargs["domain"]):
            raise serializers.ValidationError("%s is not a valid domain name." % self.kwargs["domain"])

    def _apply_filters_to_query(self, query):
        query = super(DomainNameReportByDomainDetailAPIView, self)._apply_filters_to_query(query)
        query.filter_by_domain_name(self.kwargs["domain"])
        return query


class DomainNameReportByParentDomainListAPIView(
    LatestDomainNameReportEsMixin,
    OrganizationDbMixin,
    BaseElasticsearchManyMappedAPIView,
):
    """
    This is an APIView class for retrieving the domain name scan reports for a given
    domain as well as any subdomains that data was collected for.
    """

    def _validate_arguments(self):
        if not RegexLib.domain_name_regex.match(self.kwargs["domain"]):
            raise serializers.ValidationError("%s is not a valid domain name." % self.kwargs["domain"])

    def _apply_filters_to_query(self, query):
        query = super(DomainNameReportByParentDomainListAPIView, self)._apply_filters_to_query(query)
        query.filter_by_parent_domain(self.kwargs["domain"])
        return query
