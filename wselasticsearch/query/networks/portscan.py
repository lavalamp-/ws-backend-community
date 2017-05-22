# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanQuery


class IpPortScanQuery(BaseIpAddressScanQuery):
    """
    This is an Elasticsearch query class for querying IpPortScanModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import IpPortScanModel
        return IpPortScanModel
