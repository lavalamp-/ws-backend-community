# -*- coding: utf-8 -*-
from __future__ import absolute_import

from uuid import uuid4
from mock import MagicMock
from django.utils import timezone
from mock import MagicMock

from ..mixin import ListTestCaseMixin, ParameterizedRouteMixin, ExporterTestCaseMixin, RetrieveTestCaseMixin, \
    PresentableTestCaseMixin, ExporterCustomFieldsMixin, CustomFieldsMixin, UpdateTestCaseMixin
from ..base import WsDjangoViewTestCase
from tasknode.tasks import handle_placed_order, send_emails_for_placed_order
from rest.models import Order, Receipt, ScanConfig
import rest.models


class TestOrderListView(
    ListTestCaseMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the OrderListView APIView.
    """

    _api_route = "/orders/"

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


class TestOrderDetailView(
    RetrieveTestCaseMixin,
    PresentableTestCaseMixin,
    CustomFieldsMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the OrderDetailView APIView.
    """

    _api_route = "/orders/%s/"
    _url_parameters = None

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
            order = self.get_order_for_user(user=user)
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
        import rest.models
        return rest.models.Order


class TestPlaceOrderView(
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the place_order API handler.
    """

    _api_route = "/orders/%s/place/"
    _url_parameters = None
    _orig_handle_placed_order = None
    _orig_send_emails_for_placed_order = None

    def setUp(self):
        """
        Set this test case up by stubbing out the calls to async methods.
        :return: None
        """
        super(TestPlaceOrderView, self).setUp()
        self._orig_handle_placed_order = handle_placed_order.delay
        handle_placed_order.delay = MagicMock()
        self._orig_send_emails_for_placed_order = send_emails_for_placed_order.delay
        send_emails_for_placed_order.delay = MagicMock()

    def tearDown(self):
        """
        Tear down this test case by replacing the stubbed out methods.
        :return: None
        """
        handle_placed_order.delay = self._orig_handle_placed_order
        send_emails_for_placed_order.delay = self._orig_send_emails_for_placed_order
        super(TestPlaceOrderView, self).tearDown()

    def __create_order_for_user(self, user="user_1"):
        """
        Create and return an Order that can be used for testing purposes for the given user.
        :param user: The user to create the order for.
        :return: None
        """
        user_obj = self.get_user(user=user)
        org = self.get_organization_for_user(user=user)
        return rest.models.Order.objects.create_from_user_and_organization(
            user=user_obj,
            organization=org,
        )

    def __send_place_order_request_for_user(self, input_uuid=None, user="user_1", login=True):
        """
        Send an HTTP request to the remote endpoint to invoke an order placement.
        :param input_uuid: The UUID of the order to place.
        :param user: The user to submit the request on behalf of.
        :param login: Whether or not to log in.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid is None:
            order = self.__create_order_for_user(user=user)
            input_uuid = str(order.uuid)
        self._url_parameters = input_uuid
        return self.put()

    def test_place_unknown_uuid_fails(self):
        """
        Tests that sending a request to the endpoint with an unknown UUID fails.
        :return: None
        """
        response = self.__send_place_order_request_for_user(input_uuid=str(uuid4()))
        self.assert_request_not_found(response)

    def test_no_auth_fails(self):
        """
        Tests that sending a request to the endpoint without any authentication fails.
        :return: None
        """
        response = self.__send_place_order_request_for_user(login=False)
        self.assert_request_requires_auth(response)

    def test_no_scan_privs_fails(self):
        """
        Tests that sending an order to this endpoint for an order that the requesting user does
        not own (as a regular user) fails.
        :return: None
        """
        order = self.__create_order_for_user(user="user_1")
        user = self.get_user(user="user_1")
        order.organization.scan_group.users.remove(user)
        response = self.__send_place_order_request_for_user(input_uuid=str(order.uuid))
        order.organization.scan_group.users.add(user)
        self.assert_request_not_authorized(response)

    def test_no_scan_privs_admin_succeeds(self):
        """
        Tests that sending a request to this endpoint for an order that the requesting user does not
        own (as an admin user) succeeds.
        :return: None
        """
        order = self.__create_order_for_user(user="user_1")
        response = self.__send_place_order_request_for_user(input_uuid=str(order.uuid), user="admin_1")
        self.assert_request_succeeds(response, status_code=204)

    def test_order_not_ready_fails(self):
        """
        Tests that sending a request to this endpoint for an order that is not ready to be placed fails.
        :return: None
        """
        order = self.__create_order_for_user()
        order.scan_config.delete()
        order.scan_config = None
        order.save()
        response = self.__send_place_order_request_for_user(input_uuid=str(order.uuid))
        self.assert_request_not_authorized(response)

    def test_order_is_placed(self):
        """
        Tests that sending a request to this endpoint successfully marks the order as having been placed.
        :return: None
        """
        order = self.__create_order_for_user()
        self.__send_place_order_request_for_user(input_uuid=str(order.uuid))
        order.refresh_from_db()
        self.assertTrue(order.has_been_placed)

    def test_send_emails(self):
        """
        Tests that a successful request calls send_emails_for_placed_order.delay.
        :return: None
        """
        self.__send_place_order_request_for_user()
        self.assertTrue(send_emails_for_placed_order.delay.called)

    def test_handle_placed_order(self):
        """
        Tests that a successful request calls handle_placed_order.delay.
        :return: None
        """
        self.__send_place_order_request_for_user()
        self.assertTrue(handle_placed_order.delay.called)

    def test_success_status(self):
        """
        Tests that a successful request to this endpoint returns the expected HTTP status code.
        :return: None
        """
        response = self.__send_place_order_request_for_user()
        self.assert_request_succeeds(response, status_code=204)
