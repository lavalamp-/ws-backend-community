# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import WsIntrospectionHelper
from .base import BaseOrganizationMultidocQuery


class IpAddressScanMultidocQuery(BaseOrganizationMultidocQuery):
    """
    Documentation for IpAddressScanMultidocQuery.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_classes(cls):
        from lib import WsIntrospectionHelper
        return [x[1] for x in WsIntrospectionHelper.get_ip_address_scan_query_classes()]

    # Public Methods

    def filter_by_ip_address(self, ip_address_uuid):
        """
        Apply a filter to this query to restrict results to only those results that are related to
        the given IP address.
        :param ip_address_uuid: The UUID of the IP address to filter by.
        :return: None
        """
        self.must_by_term(key="ip_address_uuid", value=ip_address_uuid)

    def filter_by_ip_address_scan(self, scan_uuid):
        """
        Apply a filter to this query to restrict results to only those results that are related to
        the given IP address scan.
        :param scan_uuid: The UUID of the IP address scan to filter by.
        :return: None
        """
        self.must_by_term(key="ip_address_scan_uuid", value=scan_uuid)

    def filter_by_latest_scan(self):
        """
        Apply a filter to this query to restrict results to only those results that
        are in the most recent domain scan.
        :return: None
        """
        self.must_by_term(key="is_latest_scan", value=True)

    def filter_by_not_ip_address_scan(self, scan_uuid):
        """
        Apply a filter to this query to restrict results to only those results that are not related to
        the given IP address scan.
        :param scan_uuid: The UUID of the IP address scan to filter against.
        :return: None
        """
        self.must_by_term(key="ip_address_scan_uuid", value=scan_uuid, include=False)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
