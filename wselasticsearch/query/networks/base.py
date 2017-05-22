# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..organizations.base import BaseOrganizationQuery


class BaseNetworkQuery(BaseOrganizationQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to
    networks.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_network(self, network_uuid):
        """
        Add a filter to this query to restrict queried data based on a network UUID.
        :param network_uuid: The UUID of the network to filter upon.
        :return: None
        """
        self.must_by_term(key="network_uuid", value=network_uuid)

    def filter_by_network_added_by(self, added_by, include=True):
        """
        Add a filter to this query to restrict queried data based on how the network was discovered.
        :param added_by: A string describing how the network was discovered.
        :param include: Whether or not to include results or exclude results by this filter.
        :return: None
        """
        self.must_by_term(key="network_added_by", value=added_by, include=include)

    def filter_by_not_user_network(self):
        """
        Add a filter to this query to restrict queried data to only those data points associated
        with networks not added by a user.
        :return: None
        """
        self.filter_by_network_added_by("user", include=False)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseIpAddressQuery(BaseNetworkQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to
    IP addresses.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_ip_address(self, ip_uuid):
        """
        Add a filter to this query to restrict queried data based on an IP address UUID.
        :param ip_uuid: The UUID of the IpAddress to filter upon.
        :return: None
        """
        self.must_by_term(key="ip_address_uuid", value=ip_uuid)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseIpAddressScanQuery(BaseIpAddressQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to IP address scans.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_ip_address_scan(self, scan_uuid):
        """
        Apply a filter to this query that restricts results to only those associated with the given IP
        address scan.
        :param scan_uuid: The UUID of the IP address scan to filter on.
        :return: None
        """
        self.must_by_term(key="ip_address_scan_uuid", value=scan_uuid)

    def filter_by_latest_scan(self):
        """
        Apply a filter to this query that restricts results to only those marked as being part of the latest
        IP address scans.
        :return: None
        """
        self.must_by_term(key="is_latest_scan", value=True)

    def filter_by_not_ip_address_scan(self, scan_uuid):
        """
        Apply a filter to this query that restricts results to only those that are not associated with the
        given IP address scan.
        :param scan_uuid: The UUID of the IP address scan to filter against.
        :return: None
        """
        self.must_by_term(key="ip_address_scan_uuid", value=scan_uuid, include=False)

    def filter_by_not_latest_scan(self):
        """
        Apply a filter to this query that restricts results to only those marked as not being a part of the
        latest IP address scans.
        :return: None
        """
        self.must_by_term(key="is_latest_scan", value=False)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
