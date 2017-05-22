# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseOrganizationMultidocQuery


class BaseWebServiceScanMultidocQuery(BaseOrganizationMultidocQuery):
    """
    This is a base query class for querying information associated with a web service scan.
    """

    def filter_by_is_latest_scan(self, is_latest=True):
        """
        Apply a filter to this query that restricts results to only those documents associated with or
        not with the last web service scan.
        :param is_latest: Whether or not results should be restricted to the latest results.
        :return: None
        """
        self.must_by_term(key="is_latest_scan", value=is_latest)

    def filter_by_latest_scan(self):
        """
        Apply a filter to this query that restricts results to only those results found in the most recent
        scan of the web service.
        :return: None
        """
        self.filter_by_is_latest_scan(is_latest=True)

    def filter_by_not_response_status(self, response_status):
        """
        Apply a filter to this query that restricts results to only those results that do not have the
        specified HTTP status code.
        :param response_status: The HTTP status code to filter against.
        :return: None
        """
        self.must_by_term(key="response_status", value=response_status, include=False)

    def filter_by_response_status(self, response_status):
        """
        Apply a filter to this query that restricts results to only those results that match the
        given response status code.
        :param response_status: The response status code to filter for.
        :return: None
        """
        self.must_by_term(key="response_status", value=response_status)

    def filter_by_url_path(self, url_path):
        """
        Apply a filter to the query that restricts results to only those results that match the
        given URL path.
        :param url_path: The URL path to restrict results to.
        :return: None
        """
        self.must_by_term(key="url_path", value=url_path)

    def filter_by_web_service(self, web_service_uuid):
        """
        Apply a filter to this query that restricts results to only those documents associated with
        the given web service.
        :param web_service_uuid: The UUID of the web service to restrict results to.
        :return: None
        """
        self.must_by_term(key="web_service_uuid", value=web_service_uuid)

    def filter_by_web_service_scan(self, web_scan_uuid):
        """
        Apply a filter to this query that restricts results to only those documents created during
        the given web service scan.
        :param web_scan_uuid: The UUID of the web service scan to restrict results to.
        :return: None
        """
        self.must_by_term(key="web_service_scan_uuid", value=web_scan_uuid)


class WebScanMultidocQuery(BaseWebServiceScanMultidocQuery):
    """
    A query class for retrieving information that was collected during a single web service scan.
    """

    @classmethod
    def get_queried_classes(cls):
        from lib import WsIntrospectionHelper
        return [x[1] for x in WsIntrospectionHelper.get_web_service_scan_query_classes()]


class WebResourceMultidocQuery(BaseWebServiceScanMultidocQuery):
    """
    A query class for retrieving information about all of the various resource type documents collected
    during a single web service scan.
    """

    @classmethod
    def get_queried_classes(cls):
        from lib import WsIntrospectionHelper
        return [x[1] for x in WsIntrospectionHelper.get_web_resource_model_classes()]
