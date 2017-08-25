# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models
from lib import WsFaker
from tests.rest_tests.base import WsDjangoViewTestCase
from tests.rest_tests.mixin import ListTestCaseMixin, PresentableTestCaseMixin, ExporterCustomFieldsMixin, \
    ExporterTestCaseMixin, RetrieveTestCaseMixin, DeleteTestCaseMixin, CustomFieldsMixin, ParameterizedRouteMixin


class TestDnsRecordTypeListView(
    ListTestCaseMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the DnsRecordTypeListView APIView.
    """

    _api_route = "/dns-record-types/"

    def __send_list_request(self, user="user_1", query_string=None, login=True):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user to send the request as.
        :param query_string: The query string to include in the URL.
        :param login: Whether or not to log the requesting user in.
        :return: The HTTP response.
                """
        if login:
            self.login(user=user)
        return self.get(query_string=query_string)

    @property
    def custom_fields_field(self):
        return "uuid"

    @property
    def custom_fields_method(self):
        return self.__send_list_request

    @property
    def list_method(self):
        return self.__send_list_request

    @property
    def presentation_method(self):
        return self.__send_list_request

    @property
    def response_has_many(self):
        return True


class TestDnsRecordTypeDetailView(
    RetrieveTestCaseMixin,
    DeleteTestCaseMixin,
    PresentableTestCaseMixin,
    CustomFieldsMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the DnsRecordTypeDetailView APIView.
    """

    _api_route = "/dns-record-types/%s/"
    _url_parameters = None

    def create_delete_object_for_user(self, user="user_1"):
        scan_config = self.get_scan_config_for_user(user=user)
        return scan_config.dns_record_types.create(**WsFaker.get_dns_record_type_kwargs())

    def __send_delete_request(self, user="user_1", login=True, query_string=None, input_uuid="POPULATE"):
        """
        Send a delete request to the API endpoint and return the response.
        :param user: The user to submit the request as.
        :param login: Whether or not to log the user in prior to sending the request.
        :param query_string: The query string to submit alongside the URL.
        :param input_uuid: The UUID of the organization to delete.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            order = self.get_dns_record_type_for_user(user=user)
            input_uuid = str(order.uuid)
        self._url_parameters = str(input_uuid)
        return self.delete(query_string=query_string)

    def __send_retrieve_request(self, user="user_1", query_string=None, login=True, input_uuid="POPULATE"):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: The user to send the request as.
        :param query_string: The query string to include in the URL.
        :param login: Whether or not to log in before sending the request.
        :param input_uuid: The UUID of the order to retrieve.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            order = self.get_dns_record_type_for_user(user=user)
            input_uuid = str(order.uuid)
        self._url_parameters = input_uuid
        return self.get(query_string=query_string)

    @property
    def custom_fields_field(self):
        return "uuid"

    @property
    def custom_fields_method(self):
        return self.__send_retrieve_request

    @property
    def delete_method(self):
        return self.__send_delete_request

    @property
    def deleted_object_class(self):
        return rest.models.DnsRecordType

    @property
    def presentation_method(self):
        return self.__send_retrieve_request

    @property
    def response_has_many(self):
        return False

    @property
    def retrieve_method(self):
        return self.__send_retrieve_request

    @property
    def retrieved_object_class(self):
        return rest.models.DnsRecordType
