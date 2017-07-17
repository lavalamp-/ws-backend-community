# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .....base import WsDjangoViewTestCase
from .....mixin import ParameterizedRouteMixin, PaginatedTestCaseMixin, DefaultViewTestCaseMixin, ExporterTestCaseMixin, \
    RelatedTestCaseMixin, PresentableTestCaseMixin, ExporterCustomFieldsMixin, CustomFieldsMixin


class TestOrganizationSslSupportReportListAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    ParameterizedRouteMixin,
    PaginatedTestCaseMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the OrganizationSslSupportReportList APIView.
    """

    _api_route = "/organizations/%s/es/ssl-support/"
    _url_parameters = None

    def __send_get_reports_request(self, user="user_1", query_string=None):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user that the request should be issued on behalf of.
        :param query_string: The query string to submit to the endpoint.
        :return: The HTTP response.
        """
        self.login(user=user)
        org = self.get_organization_for_user(user=user)
        self._url_parameters = str(org.uuid)
        return self.get(query_string=query_string)

    @property
    def custom_fields_field(self):
        return "supports_sslv2"

    @property
    def custom_fields_method(self):
        return self.__send_get_reports_request

    @property
    def presentation_method(self):
        return self.__send_get_reports_request

    @property
    def response_has_many(self):
        return True

    @property
    def send_method(self):
        return self.__send_get_reports_request


class TestOrganizationSslSupportReportAnalyticsAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the OrganizationSslSupportReportAnalyticsAPIView.
    """

    _api_route = "/organizations/%s/es/ssl-support/analytics/"
    _url_parameters = None

    def __send_get_analytics_request(self, user="user_1", query_string=None):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user that the request should be issued on behalf of.
        :param query_string: The query string to submit to the endpoint.
        :return: The HTTP response.
        """
        self.login(user=user)
        org = self.get_organization_for_user(user=user)
        self._url_parameters = str(org.uuid)
        return self.get(query_string=query_string)

    @property
    def presentation_method(self):
        return self.__send_get_analytics_request

    @property
    def send_method(self):
        return self.__send_get_analytics_request


class TestSslSupportReportDetailAPIView(
    DefaultViewTestCaseMixin,
    CustomFieldsMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the SslSupportReportDetailAPIView.
    """

    _api_route = "/ssl-support/%s/"
    _url_parameters = None

    def __send_get_report_request(self, user="user_1", query_string=None):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user that the request should be issued on behalf of.
        :param query_string: The query string to submit alongside the request.
        :return: The HTTP response.
        """
        self.login(user=user)
        network_service = self.get_network_service_for_user(user=user)
        self._url_parameters = str(network_service.uuid)
        return self.get(query_string=query_string)

    @property
    def custom_fields_field(self):
        return "supports_sslv2"

    @property
    def custom_fields_method(self):
        return self.__send_get_report_request

    @property
    def presentation_method(self):
        return self.__send_get_report_request

    @property
    def response_has_many(self):
        return False

    @property
    def send_method(self):
        return self.__send_get_report_request


class TestNetworkServiceSslSupportRelatedAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    ParameterizedRouteMixin,
    PaginatedTestCaseMixin,
    RelatedTestCaseMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the NetworkServiceSslSupportRelatedAPIView.
    """

    _api_route = "/ssl-support/%s/related-services/"
    _url_parameters = None

    def __send_get_related_request(self, user="user_1", query_string=None):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user that the request should be issued on behalf of.
        :param query_string: The query string to submit alongside the request.
        :return: The HTTP response.
        """
        self.login(user=user)
        network_service = self.get_network_service_for_user(user=user)
        self._url_parameters = str(network_service.uuid)
        return self.get(query_string=query_string)

    @property
    def custom_fields_field(self):
        return "ssl_certificate_cname"

    @property
    def custom_fields_method(self):
        return self.__send_get_related_request

    @property
    def presentation_method(self):
        return self.__send_get_related_request

    @property
    def response_has_many(self):
        return True

    @property
    def send_method(self):
        return self.__send_get_related_request
