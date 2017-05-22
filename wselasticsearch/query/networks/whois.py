# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanQuery


class IpWhoisQuery(BaseIpAddressScanQuery):
    """
    This is an Elasticsearch query class for querying IpWhoisModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import IpWhoisModel
        return IpWhoisModel
