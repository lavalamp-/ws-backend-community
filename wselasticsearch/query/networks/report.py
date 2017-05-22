# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanQuery


class IpAddressReportQuery(BaseIpAddressScanQuery):
    """
    This is an Elasticsearch query class for querying IpAddressReportModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import IpAddressReportModel
        return IpAddressReportModel

    def filter_by_has_unknown_domain_names(self):
        """
        Apply a filter to this query to restrict results to only those results that have at least one
        unknown domain names associated with them.
        :return: None
        """
        self.field_exists(field="unknown_domain_names")
