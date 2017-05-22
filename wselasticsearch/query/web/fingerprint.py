# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebServiceScanQuery


class UserAgentFingerprintQuery(BaseWebServiceScanQuery):
    """
    This is an Elasticsearch query class for querying UserAgentFingerprintModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import UserAgentFingerprintModel
        return UserAgentFingerprintModel
