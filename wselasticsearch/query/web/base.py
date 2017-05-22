# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..services.base import BaseNetworkServiceQuery


class BaseWebServiceQuery(BaseNetworkServiceQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to
    web services.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_web_service(self, web_service_uuid):
        """
        Apply a filter to this query to restrict results to the given web service.
        :param web_service_uuid: The UUID of the web service to restrict results to.
        :return: None
        """
        self.must_by_term(key="web_service_uuid", value=web_service_uuid)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseWebServiceScanQuery(BaseWebServiceQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to
    web service scans.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_latest_scan(self):
        """
        Apply a filter to this query to restrict values to only those documents that were indexed
        as the result of a web service scan.
        :return: None
        """
        self.must_by_term(key="is_latest_scan", value=True)

    def filter_by_web_service_scan(self, scan_uuid):
        """
        Apply a filter to this query to restrict results to the given web service scan.
        :param scan_uuid: The UUID of the web service scan to restrict results to.
        :return: None
        """
        self.must_by_term(key="web_service_scan_uuid", value=scan_uuid)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
