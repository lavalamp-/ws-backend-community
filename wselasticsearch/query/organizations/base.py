# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseMappedElasticsearchQuery


class BaseOrganizationQuery(BaseMappedElasticsearchQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to
    organizations.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_organization(self, org_uuid):
        """
        Add a filter to this query class to filter on an organization's UUID.
        :param org_uuid: The UUID of the organization to filter on.
        :return: None
        """
        self.must_by_term(key="org_uuid", value=org_uuid)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseOrganizationNetworkScanQuery(BaseOrganizationQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to
    organization network scans.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_network_scan(self, scan_uuid):
        """
        Add a filter to this query class to filter on an organization network scan's UUID.
        :param scan_uuid: The UUID of the organization to filter on.
        :return: None
        """
        self.must_by_term(key="org_network_scan_uuid", value=scan_uuid)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
