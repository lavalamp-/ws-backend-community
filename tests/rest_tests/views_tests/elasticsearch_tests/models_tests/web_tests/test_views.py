# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .....base import WsDjangoViewTestCase
from .....mixin import ParameterizedRouteMixin, PaginatedTestCaseMixin, DefaultViewTestCaseMixin, \
    ExporterTestCaseMixin, PresentableTestCaseMixin, CustomFieldsMixin, ExporterCustomFieldsMixin


class TestOrganizationWebServiceReportListAPIView(
    DefaultViewTestCaseMixin,
    ParameterizedRouteMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    PaginatedTestCaseMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the OrganizationWebServiceReportList APIView.
    """

    _api_route = "/organizations/%s/web-services/"
    _url_parameters = None

    def __send_get_reports_request(self, user="user_1", query_string=None):
        """
        Send an HTTP request to the configure API endpoint and return the response.
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
        return "hostname_resolves"

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


class TestOrganizationWebServiceReportAnalyticsAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the OrganizationWebServiceReportAnalyticsAPIView.
    """

    _api_route = "/organizations/%s/web-services/analytics/"
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


class TestWebServiceResourceListAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    ParameterizedRouteMixin,
    PaginatedTestCaseMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the WebServiceResourceListAPIView.
    """

    _api_route = "/web-services/%s/resources/"
    _url_parameters = None

    def __send_get_resources_request(self, user="user_1", query_string=None):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user that the request should be issued on behalf of.
        :param query_string: The query string to submit to the endpoint.
        :return: The HTTP response.
        """
        self.login(user=user)
        web_service = self.get_web_service_for_user(user=user)
        self._url_parameters = str(web_service.uuid)
        return self.get(query_string=query_string)

    @property
    def custom_fields_field(self):
        return "url_path"

    @property
    def custom_fields_method(self):
        return self.__send_get_resources_request

    @property
    def presentation_method(self):
        return self.__send_get_resources_request

    @property
    def response_has_many(self):
        return True

    @property
    def send_method(self):
        return self.__send_get_resources_request


class TestWebServiceResourceAnalyticsAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the WebServiceResourceAnalyticsAPIView.
    """

    _api_route = "/web-services/%s/resources/analytics/"
    _url_parameters = None

    def __send_get_analytics_request(self, user="user_1", query_string=None):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user that the request should be issued on behalf of.
        :param query_string: The query string to submit to the endpoint.
        :return: The HTTP response.
        """
        self.login(user=user)
        web_service = self.get_web_service_for_user(user=user)
        self._url_parameters = str(web_service.uuid)
        return self.get(query_string=query_string)

    @property
    def presentation_method(self):
        return self.__send_get_analytics_request

    @property
    def send_method(self):
        return self.__send_get_analytics_request

