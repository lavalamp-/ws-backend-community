# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..organizations.base import BaseOrganizationQuery


class BaseDomainNameQuery(BaseOrganizationQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to domain names.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_domain_added_by(self, added_by, include=True):
        """
        Add a filter to this query to restrict queried data based on how the domain was discovered.
        :param added_by: A string describing how the domain was discovered.
        :param include: Whether or not to include/exclude matching results.
        :return: None
        """
        self.must_by_term(key="domain_added_by", value=added_by, include=include)

    def filter_by_domain_name(self, domain_uuid):
        """
        Add a filter to this query to restrict queried data base on a domain name UUID.
        :param domain_uuid: The UUID of the domain name.
        :return: None
        """
        self.must_by_term(key="domain_uuid", value=domain_uuid)

    def filter_by_not_user_domain(self):
        """
        Apply a filter to this query to restrict results to only those domains that were not added
        by a user.
        :return: None
        """
        self.filter_by_domain_added_by(added_by="user", include=False)

    def filter_by_user_domain(self):
        """
        Apply a filter to this query to restrict results to only those domains that were added by
        a user.
        :return: None
        """
        self.filter_by_domain_added_by(added_by="user")

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseDomainNameScanQuery(BaseDomainNameQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to domain name scans.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_domain_name_scan(self, scan_uuid):
        """
        Add a filter to this query to restrict queried data based on a domain name scan UUID.
        :param scan_uuid: The UUID of the domain name scan.
        :return: None
        """
        self.must_by_term(key="domain_scan_uuid", value=scan_uuid)

    def filter_by_latest_scan(self):
        """
        Add a filter to this query to restrict queried data to only those results retrieved during
        the most recent scan for the domain.
        :return: None
        """
        self.must_by_term(key="is_latest_scan", value=True)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
