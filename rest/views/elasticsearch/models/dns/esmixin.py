# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..mixin import BaseEsMixin


class DomainNameReportEsMixin(BaseEsMixin):
    """
    This is a mixin class for APIViews that query domain name report models.
    """

    @classmethod
    def get_es_query_class(cls):
        from wselasticsearch.query import DomainNameReportQuery
        return DomainNameReportQuery

    def _apply_aggregates_to_query(self, query):
        return query


class LatestDomainNameReportEsMixin(DomainNameReportEsMixin):
    """
    This is a mixin class for APIViews that query domain name report models that are
    members of the most recent scans for the investigated domain names.
    """

    def _apply_filters_to_query(self, query):
        query = super(LatestDomainNameReportEsMixin, self)._apply_filters_to_query(query)
        query.filter_by_latest_scan()
        return query
