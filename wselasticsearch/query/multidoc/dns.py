# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import WsIntrospectionHelper
from .base import BaseOrganizationMultidocQuery


class DomainNameMultidocQuery(BaseOrganizationMultidocQuery):
    """
    A query class for retrieving information about domain names across multiple Elasticsearch
    model types.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_classes(cls):
        to_return = WsIntrospectionHelper.get_domain_name_mixin_model_classes()
        return [x[1] for x in to_return]

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class DomainNameScanMultidocQuery(BaseOrganizationMultidocQuery):
    """
    This is a query class for retrieving information about all models associated with domain
    name scans.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_classes(cls):
        from lib import WsIntrospectionHelper
        return [x[1] for x in WsIntrospectionHelper.get_domain_name_scan_query_classes()]

    # Public Methods

    def filter_by_domain_name(self, domain_uuid):
        """
        Apply a filter to this query to restrict results to only those results that
        match the given domain.
        :param domain_uuid: The UUID of the domain name to filter on.
        :return: None
        """
        self.must_by_term(key="domain_uuid", value=domain_uuid)

    def filter_by_domain_name_scan(self, scan_uuid):
        """
        Apply a filter to this query to restrict results to only those results that
        match the given domain name scan.
        :param scan_uuid: The UUID of the domain name scan to filter on.
        :return: None
        """
        self.must_by_term(key="domain_scan_uuid", value=scan_uuid)

    def filter_by_latest_scan(self):
        """
        Apply a filter to this query to restrict results to only those results that
        are in the most recent domain scan.
        :return: None
        """
        self.must_by_term(key="is_latest_scan", value=True)

    def filter_by_not_domain_name_scan(self, scan_uuid):
        """
        Apply a filter to this query to restrict results to only those results that do not
        match the given domain name scan.
        :param scan_uuid: The UUID of the domain name scan to filter on.
        :return: None
        """
        self.must_by_term(key="domain_scan_uuid", value=scan_uuid, include=False)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
