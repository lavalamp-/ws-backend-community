# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..networks.base import BaseIpAddressQuery


class BaseNetworkServiceQuery(BaseIpAddressQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to
    network services.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_network_service(self, service_uuid):
        """
        Add a filter to this query that restricts results to the given network service.
        :param service_uuid: The UUID of the NetworkService to filter upon.
        :return: None
        """
        self.must_by_term(key="network_service_uuid", value=service_uuid)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseNetworkServiceScanQuery(BaseNetworkServiceQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to
    network service scans.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_latest_scan(self):
        """
        Add a filter to this query that restricts results to the most recent network service scans.
        :return: None
        """
        self.must_by_term(key="is_latest_scan", value=True)

    def filter_by_network_service_scan(self, scan_uuid):
        """
        Add a filter to this query that restricts results to the given network service scan.
        :param scan_uuid: The UUID of the NetworkService to filter upon.
        :return: None
        """
        self.must_by_term(key="network_service_scan_uuid", value=scan_uuid)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
