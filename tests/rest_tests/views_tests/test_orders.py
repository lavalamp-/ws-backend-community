# -*- coding: utf-8 -*-
from __future__ import absolute_import

from uuid import uuid4
from mock import MagicMock
from django.utils import timezone

from lib import WsStripeHelper
from ..mixin import ListTestCaseMixin, ParameterizedRouteMixin, ExporterTestCaseMixin, RetrieveTestCaseMixin, \
    PresentableTestCaseMixin, ExporterCustomFieldsMixin, CustomFieldsMixin
from ..base import WsDjangoViewTestCase
from tasknode.tasks import handle_placed_order, send_emails_for_placed_order
from rest.models import Order, Receipt


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


class TestPlaceOrder(
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the place_order function APIView.
    """

    _api_route = "/orders/%s/place/"
    _url_parameters = None
    _original_delay_method = None
    _original_place_method = None
    _original_send_method = None
    _original_get_receipt_method = None

    def setUp(self):
        """
        Set up this test case by mocking out handle_placed_order.delay and Order.place_order.
        :return: None
        """
        super(TestPlaceOrder, self).setUp()
        self._original_delay_method = handle_placed_order.delay
        handle_placed_order.delay = MagicMock()
        self._original_place_method = Order.place_order
        Order.place_order = MagicMock()
        self._original_send_method = send_emails_for_placed_order.delay
        send_emails_for_placed_order.delay = MagicMock()
        self._original_get_receipt_method = Order.get_receipt_description
        Order.get_receipt_description = MagicMock()

    def tearDown(self):
        """
        Tear down this test case by returning handle_placed_order.delay and Order.place_order to their original
        methods.
        :return: None
        """
        handle_placed_order.delay = self._original_delay_method
        Order.place_order = self._original_place_method
        send_emails_for_placed_order.delay = self._original_send_method
        Order.get_receipt_description = self._original_get_receipt_method
        super(TestPlaceOrder, self).tearDown()

    def __send_place_request(self, user="user_1", query_string=None, login=True, input_uuid="POPULATE"):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: The user to send the request as.
        :param query_string: The query string to include in the URL.
        :param login: Whether or not to log in before sending the request.
        :param input_uuid: The UUID of the order to place.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            order = self.get_order_for_user(user=user)
            input_uuid = str(order.uuid)
        self._url_parameters = input_uuid
        return self.put(query_string=query_string)

    def test_unknown_uuid_fails(self):
        """
        Tests that submitting a request to the API endpoint with an unknown UUID fails.
        :return: None
        """
        self.assert_request_fails(self.send(input_uuid=str(uuid4())), fail_status=404)

    def test_no_scan_privileges_fails(self):
        """
        Tests that submitting a request on behalf of a user that does not have scan privileges fails.
        :return: None
        """
        order = self.get_order_for_user(user="user_1")
        scan_user = order.organization.scan_group.users.first()
        order.organization.scan_group.users.remove(scan_user)
        response = self.send(user="user_1")
        order.organization.scan_group.users.add(scan_user)
        self.assert_request_not_authorized(response)

    def test_order_already_charged_fails(self):
        """
        Tests that submitting a request with the UUID of an order that has already been charged fails.
        :return: None
        """
        order = self.get_order_for_user(user="user_1")
        order.has_been_charged = True
        order.charged_at = timezone.now()
        order.save()
        response = self.send(user="user_1")
        order.has_been_charged = False
        order.charged_at = None
        order.save()
        self.assert_request_fails(response)

    def test_calls_place_order(self):
        """
        Tests that submitting a request correctly calls place_order.
        :return: None
        """
        self.send()
        self.assertTrue(Order.place_order.called)

    def test_place_order_false_fails(self):
        """
        Tests that submitting a request that results in a False-y value being returned by place_order fails.
        :return: None
        """
        Order.place_order.return_value = False
        self.assert_request_fails(self.send())

    def test_success_status(self):
        """
        Tests to check that a successful placement request returns the expected HTTP status code.
        :return: None
        """
        response = self.send()
        self.assertEqual(response.status_code, 204)

    def test_success_handle_placed_called(self):
        """
        Tests to check that a successful placement request calls handle_placed_order.delay.
        :return: None
        """
        self.send()
        self.assertTrue(handle_placed_order.delay.called)

    def test_success_handle_placed_called_with(self):
        """
        Tests to check that a successful placement request calls handle_placed_order.delay with the expected
        arguments.
        :return: None
        """
        order = self.get_order_for_user(user="user_1")
        self.send(user="user_1")
        handle_placed_order.delay.assert_called_with(order_uuid=unicode(order.uuid))

    def test_success_calls_send_emails(self):
        """
        Tests to check that a successful placement request calls send_emails_for_placed_order.delay.
        :return: None
        """
        self.send()
        self.assertTrue(send_emails_for_placed_order.delay.called)

    @property
    def send_method(self):
        return self.__send_place_request
