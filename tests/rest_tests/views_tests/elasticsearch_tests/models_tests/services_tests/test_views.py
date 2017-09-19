# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models
from wselasticsearch.query import SslSupportReportQuery
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


class TestSslSupportReportByIpListAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    ExporterTestCaseMixin,
    ExporterCustomFieldsMixin,
    PaginatedTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the SslSupportReportByIpListAPIView APIView.
    """

    _api_route = "/organizations/%s/es/ssl-support/by-ip/%s/"
    _url_parameters = None

    def __send_list_request(
            self,
            user="user_1",
            login=True,
            input_uuid="POPULATE",
            query_string=None,
            ip_addr_uuid="POPULATE",
            addr_override=None,
    ):
        """
        Send a list request to the API endpoint and return the response.
        :param user: The user to submit the request as.
        :param login: Whether or not to log in prior to submitting the request.
        :param input_uuid: The UUID of the organization that is being queried.
        :param query_string: The query string to include in the request.
        :param ip_addr_uuid: The IP address to populate the URL parameters from.
        :param addr_override: A value to supply to the IP address URL parameter.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            organization = self.get_organization_for_user(user=user)
            input_uuid = organization.uuid
        else:
            organization = rest.models.Organization.objects.get(pk=input_uuid)
        if ip_addr_uuid == "POPULATE":
            ip_address = organization.ip_addresses.first()
        else:
            ip_address = rest.models.IpAddress.objects.get(pk=ip_addr_uuid)
        if addr_override is not None:
            self._url_parameters = str(input_uuid), addr_override
        else:
            self._url_parameters = str(input_uuid), ip_address.address
        return self.get(query_string=query_string)

    def test_get_invalid_ip_fails(self):
        """
        Tests that submitting a request to this endpoint to search by an invalid IP address
        value fails.
        :return: None
        """
        self.assert_request_fails(self.__send_list_request(addr_override="ASDLMASDO"))

    def test_get_by_ip_address_succeeds(self):
        """
        Tests that submitting a request to this endpoint to search by IP address succeeds.
        :return: None
        """
        self.assert_request_succeeds(self.__send_list_request())

    @property
    def custom_fields_field(self):
        return "ip_address_uuid"

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


class TestSslSupportReportByDomainListAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    ExporterTestCaseMixin,
    ExporterCustomFieldsMixin,
    PaginatedTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for the SslSupportReportByDomainListAPIView APIView.
    """

    _api_route = "/organizations/%s/es/ssl-support/by-domain/%s/"
    _url_parameters = None

    def __send_list_request(
            self,
            user="user_1",
            login=True,
            input_uuid="POPULATE",
            query_string=None,
            domain_uuid="POPULATE",
            domain_override=None,
    ):
        """
        Send a list request to the API endpoint and return the response.
        :param user: The user to submit the request as.
        :param login: Whether or not to log in prior to submitting the request.
        :param input_uuid: The UUID of the organization that is being queried.
        :param query_string: The query string to include in the request.
        :param domain_uuid: The domain to populate the URL parameters from.
        :param domain_override: A value to supply to the domain URL parameter.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            organization = self.get_organization_for_user(user=user)
            input_uuid = organization.uuid
        else:
            organization = rest.models.Organization.objects.get(pk=input_uuid)
        if domain_uuid == "POPULATE":
            query = SslSupportReportQuery()
            query.filter_by_organization(organization.uuid)
            query.filter_by_latest_scan()
            response = query.search(organization.uuid)
            domain = response.results[0]["_source"]["cert_subject_common_name"]
        else:
            domain = rest.models.DomainName.objects.get(pk=domain_uuid).name
        if domain_override is not None:
            self._url_parameters = str(input_uuid), domain_override
        else:
            self._url_parameters = str(input_uuid), domain
        return self.get(query_string=query_string)

    def test_get_invalid_domain_fails(self):
        """
        Tests that submitting a request to this endpoint to search by an invalid domain name
        value fails.
        :return: None
        """
        self.assert_request_fails(self.__send_list_request(domain_override="** **"))

    def test_get_by_domain_succeeds(self):
        """
        Tests that submitting a request to this endpoint to search by domain name succeeds.
        :return: None
        """
        self.assert_request_succeeds(self.__send_list_request())

    @property
    def custom_fields_field(self):
        return "ip_address_uuid"

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
