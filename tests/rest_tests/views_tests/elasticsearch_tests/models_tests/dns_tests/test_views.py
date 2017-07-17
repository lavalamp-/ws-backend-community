# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .....base import WsDjangoViewTestCase
from .....mixin import ParameterizedRouteMixin, PaginatedTestCaseMixin, DefaultViewTestCaseMixin, \
    ExporterTestCaseMixin, PresentableTestCaseMixin, ExporterCustomFieldsMixin, CustomFieldsMixin


class OrganizationDomainNameReportListAPIView(
    DefaultViewTestCaseMixin,
    ParameterizedRouteMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    PaginatedTestCaseMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the OrganizationDomainNameReportListAPIView view.
    """

    _api_route = "/organizations/%s/es/domain-names/"
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
        return "domain_name"

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


class TestOrganizationDomainNameReportAnalyticsAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the OrganizationDomainNameReportAnalyticsAPIView view.
    """

    _api_route = "/organizations/%s/es/domain-names/analytics/"
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


class TestDomainNameReportDetailAPIView(
    DefaultViewTestCaseMixin,
    CustomFieldsMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the DomainNameReportDetailAPIView view.
    """

    _api_route = "/domain-names/%s/es/report/"
    _url_parameters = None

    def __send_get_report_request(self, user="user_1", query_string=None):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user that the request should be issued on behalf of.
        :param query_string: The query string to submit alongside the request.
        :return: The HTTP response.
        """
        self.login(user=user)
        domain_name = self.get_domain_name_for_user(user=user)
        self._url_parameters = str(domain_name.uuid)
        return self.get(query_string=query_string)

    @property
    def custom_fields_field(self):
        return "domain_name"

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
