# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from .base import BaseDomainNameScanQuery

logger = logging.getLogger(__name__)


class DnsRecordQuery(BaseDomainNameScanQuery):
    """
    This is an Elasticsearch query class for querying DnsRecordModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import DnsRecordModel
        return DnsRecordModel

    # Public Methods

    def filter_by_contains_ip_address(self):
        """
        Add a filter to this query to restrict results to only those entries that contain
        IP addresses.
        :return: None
        """
        self.must_by_term(key="contains_ip_address", value=True)

    def filter_by_ip_address(self, ip_address):
        """
        Apply filters to this query to restrict results to only those that contain IP addresses and
        match the given IP address.
        :param ip_address: The IP address to query by.
        :return: None
        """
        self.filter_by_contains_ip_address()
        self.must_by_term(key="record_content", value=ip_address)

    def filter_by_subdomain(self, parent_domain):
        """
        Apply a filter to this query to restrict results to only those results that represent subdomains
        of the given domain.
        :param parent_domain: The parent domain to search for.
        :return: None
        """
        if "." not in parent_domain:
            logger.warning(
                "No dot found in parent domain of %s."
                % (parent_domain,)
            )
        subdomain_query = ".%s" % (parent_domain,)
        self.must_by_wildcard(key="domain_name", value=subdomain_query, wild_before=True, wild_after=False)
        self.must_by_term(key="domain_name", value=parent_domain, include=False)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
