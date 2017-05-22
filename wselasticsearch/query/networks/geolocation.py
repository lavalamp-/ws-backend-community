# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanQuery


class IpGeolocationQuery(BaseIpAddressScanQuery):
    """
    This is an Elasticsearch query class for querying IpGeolocationModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import IpGeolocationModel
        return IpGeolocationModel
