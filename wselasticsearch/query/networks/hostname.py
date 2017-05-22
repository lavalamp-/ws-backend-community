# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanQuery


class IpReverseHostnameQuery(BaseIpAddressScanQuery):
    """
    This is an Elasticsearch query class for querying IpReverseHostnameModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import IpReverseHostnameModel
        return IpReverseHostnameModel
