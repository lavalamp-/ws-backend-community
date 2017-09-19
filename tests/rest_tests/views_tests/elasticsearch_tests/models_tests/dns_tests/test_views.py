# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models
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


class TestDomainNameReportByDomainDetailAPIView(
    DefaultViewTestCaseMixin,
    CustomFieldsMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for the DomainNameReportByDomainDetailAPIView APIView.
    """

    _api_route = "/organizations/%s/es/domain-names/by-domain/%s/"
    _url_parameters = None

    def __send_get_report_request(
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
        :param domain_uuid: The domain name to populate the URL parameters from.
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
            domain = organization.domain_names.first()
        else:
            domain = rest.models.DomainName.objects.get(pk=domain_uuid)
        if domain_override is not None:
            self._url_parameters = str(input_uuid), domain_override
        else:
            self._url_parameters = str(input_uuid), domain.name
        return self.get(query_string=query_string)

    def test_get_unknown_domain_fails(self):
        """
        Tests that submitting a request to this endpoint for a domain that does not exist returns
        the expected status code.
        :return: None
        """
        self.assert_request_not_found(self.__send_get_report_request(domain_override="www.foo.baz.bang.com.foo"))

    def test_get_invalid_domain_fails(self):
        """
        Tests that submitting a request to this endpoint to search by an invalid domain
        value fails.
        :return: None
        """
        self.assert_request_fails(self.__send_get_report_request(domain_override="** **"))

    def test_get_by_domain_succeeds(self):
        """
        Tests that submitting a request to this endpoint to search by domain succeeds.
        :return: None
        """
        self.assert_request_succeeds(self.__send_get_report_request())

    @property
    def custom_fields_field(self):
        return "domain_uuid"

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


class TestDomainNameReportByParentDomainListAPIView(
    DefaultViewTestCaseMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    ParameterizedRouteMixin,
    PaginatedTestCaseMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for the DomainNameReportByParentDomainListAPIView APIView.
    """

    _api_route = "/organizations/%s/es/domain-names/by-parent-domain/%s/"
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
        :param domain_uuid: The domain name to populate the URL parameters from.
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
            domain = organization.domain_names.first()
        else:
            domain = rest.models.DomainName.objects.get(pk=domain_uuid)
        if domain_override is not None:
            self._url_parameters = str(input_uuid), domain_override
        else:
            self._url_parameters = str(input_uuid), domain.name
        return self.get(query_string=query_string)

    def test_get_invalid_domain_fails(self):
        """
        Tests that submitting a request to this endpoint to search by an invalid domain
        value fails.
        :return: None
        """
        self.assert_request_fails(self.__send_list_request(domain_override="** **"))

    def test_get_by_domain_succeeds(self):
        """
        Tests that submitting a request to this endpoint to search by domain succeeds.
        :return: None
        """
        self.assert_request_succeeds(self.__send_list_request())

    @property
    def custom_fields_field(self):
        return "domain_uuid"

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
