# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseDomainNameScanQuery


class DomainNameReportQuery(BaseDomainNameScanQuery):
    """
    This is an Elasticsearch query class for querying DomainNameReportModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import DomainNameReportModel
        return DomainNameReportModel
