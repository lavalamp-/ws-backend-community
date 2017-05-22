# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseOrganizationMultidocQuery


class NetworkServiceScanMultidocQuery(BaseOrganizationMultidocQuery):
    """
    This is a query class for retrieving information about all models associated with network
    service scans.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_classes(cls):
        from lib import WsIntrospectionHelper
        return [x[1] for x in WsIntrospectionHelper.get_network_service_scan_query_classes()]

    # Public Methods

    def filter_by_latest_scan(self):
        """
        Apply a filter to this query to restrict results to only those results associated with
        the most recent scan.
        :return: None
        """
        self.must_by_term(key="is_latest_scan", value=True)

    def filter_by_network_service(self, service_uuid):
        """
        Apply a filter to this query to restrict results to only those results associated with
        the given network service.
        :param service_uuid: The UUID of the network service to filter on.
        :return: None
        """
        self.must_by_term(key="network_service_uuid", value=service_uuid)

    def filter_by_network_service_scan(self, scan_uuid):
        """
        Apply a filter to this query to restrict results to only those results associated with
        the given network service scan.
        :param scan_uuid: The UUID of the network service scan to restrict results to.
        :return: None
        """
        self.must_by_term(key="network_service_scan_uuid", value=scan_uuid)

    def filter_by_not_network_service_scan(self, scan_uuid):
        """
        Apply a filter to this query to restrict results to only those results that are not a part
        of the given network service scan.
        :param scan_uuid: The UUID of the network service scan to exclude from results.
        :return: None
        """
        self.must_by_term(key="network_service_scan_uuid", value=scan_uuid, include=False)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
