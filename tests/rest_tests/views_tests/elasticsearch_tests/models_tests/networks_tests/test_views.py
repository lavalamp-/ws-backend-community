# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models
from .....base import WsDjangoViewTestCase
from .....mixin import ParameterizedRouteMixin, PaginatedTestCaseMixin, DefaultViewTestCaseMixin, \
    ExporterTestCaseMixin, PresentableTestCaseMixin, CustomFieldsMixin, ExporterCustomFieldsMixin


class TestOrganizationIpAddressReportListAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    ParameterizedRouteMixin,
    PaginatedTestCaseMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the OrganizationIpAddressReportListAPIView APIView.
    """

    _api_route = "/organizations/%s/es/ip-addresses/"
    _url_parameters = None

    def __send_list_request(self, user="user_1", login=True, input_uuid="POPULATE", query_string=None):
        """
        Send an HTTP request to the configured endpoint and return the response.
        :param user: The user to log in as.
        :param login: Whether or not to log in.
        :param input_uuid: The UUID of the organization to request IP address reports for.
        :param query_string: The query string to supply in the request.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            organization = self.get_organization_for_user(user=user)
            input_uuid = organization.uuid
        self._url_parameters = str(input_uuid)
        return self.get(query_string=query_string)

    @property
    def custom_fields_field(self):
        return "org_uuid"

    @property
    def custom_fields_method(self):
        return self.__send_list_request

    @property
    def presentation_method(self):
        return self.__send_list_request

    @property
    def response_has_many(self):
        return True

    @property
    def send_method(self):
        return self.__send_list_request


class TestOrganizationIpAddressReportAnalyticsAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the OrganizationIpAddressReportAnalyticsAPIView APIView.
    """

    _api_route = "/organizations/%s/es/ip-addresses/analytics/"
    _url_parameters = None

    def __send_analytics_request(self, user="user_1", login=True, input_uuid="POPULATE", query_string=None):
        """
        Send an HTTP request to the configured endpoint and return the response.
        :param user: The user to log in as.
        :param login: Whether or not to log in.
        :param input_uuid: The UUID of the organization to request IP address reports for.
        :param query_string: The query string to supply in the request.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            organization = self.get_organization_for_user(user=user)
            input_uuid = organization.uuid
        self._url_parameters = str(input_uuid)
        return self.get(query_string=query_string)

    @property
    def presentation_method(self):
        return self.__send_analytics_request

    @property
    def send_method(self):
        return self.__send_analytics_request


class TestIpAddressReportDetailAPIView(
    DefaultViewTestCaseMixin,
    CustomFieldsMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the IpAddressReportDetailAPIView APIView.
    """

    _api_route = "/ip-addresses/%s/es/"
    _url_parameters = None

    def __send_get_report_request(self, user="user_1", login=True, input_uuid="POPULATE", query_string=None):
        """
        Send an HTTP request to the configured endpoint and return the response.
        :param user: The user to log in as.
        :param login: Whether or not to log in.
        :param input_uuid: The UUID of the IP address to request a report for.
        :param query_string: The query string to supply in the request.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            ip_address = self.get_ip_address_for_user(user=user)
            input_uuid = ip_address.uuid
        self._url_parameters = str(input_uuid)
        return self.get(query_string=query_string)

    @property
    def custom_fields_field(self):
        return "ip_address_uuid"

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
