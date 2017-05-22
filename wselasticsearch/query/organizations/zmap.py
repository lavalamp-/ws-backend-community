# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseOrganizationNetworkScanQuery


class ZmapScanResultQuery(BaseOrganizationNetworkScanQuery):
    """
    This is an Elasticsearch query class for querying ZmapScanResultModel objects.
    """
    
    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import ZmapScanResultModel
        return ZmapScanResultModel

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
