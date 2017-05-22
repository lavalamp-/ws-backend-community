# -*- coding: utf-8 -*-
from __future__ import absolute_import


class OrganizationQueryMixin(object):
    """
    A mixin class for enabling queries to filter by organization.
    """

    def filter_by_organization(self, org_uuid):
        """
        Add a filter to this query to restrict results to the given organization.
        :param org_uuid: The UUID of the organization to filter on.
        :return: None
        """
        self.filter_by_term(key="org_uuid", value=org_uuid)


class ScanQueryMixin(OrganizationQueryMixin):
    """
    A mixin class for enabling queries to filter by organization and scan.
    """

    @classmethod
    def get_query_for_scan(cls, scan_uuid=None, org_uuid=None):
        """
        Create and return a new SslSupportQuery that is already configured to filter on the
        given scan and organization.
        :param scan_uuid: The UUID of the scan to filter on.
        :param org_uuid: The UUID of the organization to filter on.
        :return: A new SslSupportQuery that is configured to filter on the given scan and organization.
        """
        to_return = cls()
        to_return.filter_by_organization(org_uuid)
        to_return.filter_by_scan(scan_uuid)
        return to_return

    def filter_by_scan(self, scan_uuid):
        """
        Add a filter to this query to restrict results to the given scan.
        :param scan_uuid: The UUID of the scan to filter on.
        :return: None
        """
        self.filter_by_term(key="scan_uuid", value=scan_uuid)
