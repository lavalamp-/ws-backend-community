# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseNetworkServiceScanQuery


class NetworkServiceLivenessQuery(BaseNetworkServiceScanQuery):
    """
    This is an Elasticsearch query class for querying NetworkServiceLivenessModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import NetworkServiceLivenessModel
        return NetworkServiceLivenessModel

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
