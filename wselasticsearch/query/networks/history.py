# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanQuery


class IpDomainHistoryQuery(BaseIpAddressScanQuery):
    """
    This is an Elasticsearch query class for querying IpDomainHistoryModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import IpDomainHistoryModel
        return IpDomainHistoryModel
