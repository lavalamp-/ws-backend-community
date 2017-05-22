# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseNetworkServiceScanQuery


class ServiceFingerprintQuery(BaseNetworkServiceScanQuery):
    """
    This is an Elasticsearch query class for querying ServiceFingerprintModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import ServiceFingerprintModel
        return ServiceFingerprintModel

    # Public Methods

    def filter_by_successful_fingerprints(self):
        """
        Apply a filter to this query to restrict results to only those fingerprints that
        were successful.
        :return: None
        """
        self.must_by_term(key="fingerprint_result", value=True)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class VirtualHostFingerprintQuery(BaseNetworkServiceScanQuery):
    """
    This is an Elasticsearch query class for querying VirtualHostFingerprintModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import VirtualHostFingerprintModel
        return VirtualHostFingerprintModel

    # Public Methods

    def filter_by_over_ssl(self, value):
        """
        Add a filter to this query to filter results to only those fingerprints that either were or
        were not retrieved over SSL based on the value.
        :param value: Whether or not fingerprints were retrieved over SSL.
        :return: None
        """
        self.must_by_term(key="over_ssl", value=value)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
