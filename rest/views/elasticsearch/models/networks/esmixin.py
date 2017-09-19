# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..mixin import BaseEsMixin


class IpAddressReportEsMixin(BaseEsMixin):
    """
    This is a mixin class for APIViews that query IP address report models.
    """

    @classmethod
    def get_es_query_class(cls):
        from wselasticsearch.query import IpAddressReportQuery
        return IpAddressReportQuery

    def _apply_aggregates_to_query(self, query):
        query.aggregate_on_term(key="geolocation_region", name="geolocation_region")
        query.aggregate_on_term(key="geolocation_country_code", name="geolocation_country_code")
        query.aggregate_on_term(key="geolocation_postal_code", name="geolocation_postal_code")
        query.aggregate_on_term(key="network_cidr_range", name="network_cidr_range")
        return query


class LatestIpAddressReportEsMixin(IpAddressReportEsMixin):
    """
    This is a mixin class for APIViews that query IP address report models that are members of
    the most recent scans for the investigated IP addresses.
    """

    def _apply_filters_to_query(self, query):
        query = super(LatestIpAddressReportEsMixin, self)._apply_filters_to_query(query)
        query.filter_by_latest_scan()
        return query
