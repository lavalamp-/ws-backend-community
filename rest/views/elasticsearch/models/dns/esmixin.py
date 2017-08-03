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
        query.aggregate_on_term(key="has_resolutions", name="has_resolutions")
        query.aggregate_on_term(key="related_ips.ip_address", name="related_ips")
        query.aggregate_on_term(key="resolutions.record_type", name="resolution_type")
        query.aggregate_on_term(key="domain_added_by", name="domain_added_by")
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
