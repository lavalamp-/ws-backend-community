# -*- coding: utf-8 -*-
from __future__ import absolute_import

from mock import MagicMock

from ..mixin import ListTestCaseMixin, ExporterTestCaseMixin, CreateForUserTestCaseMixin, RetrieveTestCaseMixin, \
    DeleteTestCaseMixin, ParameterizedRouteMixin, PresentableTestCaseMixin, ExporterCustomFieldsMixin, \
    CustomFieldsMixin
from ..base import WsDjangoViewTestCase
from lib import WsStripeHelper, WsFaker
import rest.models


class TestPaymentTokenListView(
    ListTestCaseMixin,
    CreateForUserTestCaseMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for the PaymentTokenListView APIView.
    """

    _api_route = "/payment-tokens/"

    def setUp(self):
        super(TestPaymentTokenListView, self).setUp()
        WsStripeHelper.create_stripe_user_from_token = MagicMock()

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

    def __send_create_request(
            self,
            user="user_1",
            query_string=None,
            login=True,
            include_name=True,
            name="My Payment Token",
            include_token_type=True,
            token_type="stripe",
            include_token_value=True,
            token_value="tok_19xg6sE6xi5DHYsI80fJIOYY",
            include_card_type=True,
            card_type="American Express",
            include_expiration_month=True,
            expiration_month=1,
            include_expiration_year=True,
            expiration_year=2020,
            include_card_last_four=True,
            card_last_four="1234",
    ):
        """
        Send an HTTP request to the configured API endpoint to create a new payment token and
        return the HTTP response.
        :param user: A string depicting the user to submit the request as.
        :param query_string: The query string to include in the URL.
        :param login: Whether or not to log the requesting user in before sending the request.
        :param include_name: Whether or not to include the name in the request.
        :param name: The name to include in the request.
        :param include_token_type: Whether or not to include the token type in the request.
        :param token_type: The token type to include in the request.
        :param include_token_value: Whether or not to include the token value in the request.
        :param token_value: The token value to include in the request.
        :param include_card_type: Whether or not to include the card type in the request.
        :param card_type: The card type to include in the request.
        :param include_expiration_month: Whether or not to include the expiration month in the request.
        :param expiration_month: The expiration month to include in the request.
        :param include_expiration_year: Whether or not to include the expiration year in the request.
        :param expiration_year: The expiration year to include in the request.
        :param include_card_last_four: Whether or not to include the last four digits of the credit card
        in the request.
        :param card_last_four: Last four card numbers to include in the request.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        to_send = {}
        if include_name:
            to_send["name"] = name
        if include_token_type:
            to_send["token_type"] = token_type
        if include_token_value:
            to_send["token_value"] = token_value
        if include_card_type:
            to_send["card_type"] = card_type
        if include_expiration_month:
            to_send["expiration_month"] = expiration_month
        if include_expiration_year:
            to_send["expiration_year"] = expiration_year
        if include_card_last_four:
            to_send["card_last_four"] = card_last_four
        return self.post(query_string=query_string, data=to_send)

    def test_create_no_name_succeeds(self):
        """
        Tests that submitting a create request without a name succeeds.
        :return: None
        """
        self.assert_creation_succeeds(self.send_create_request(include_name=False))

    def test_create_empty_name_succeeds(self):
        """
        Tests that submitting a create request with an empty name succeeds.
        :return: None
        """
        self.assert_creation_succeeds(self.send_create_request(name=None))

    def test_create_assigns_correct_name(self):
        """
        Tests that submitting a create request assigns the correct value to name.
        :return: None
        """
        response = self.send_create_request(name="FOOBAR")
        token = self.get_last_created_payment_token()
        self.assertEqual(token.name, "FOOBAR")

    def test_create_no_token_type_fails(self):
        """
        Tests that submitting a create request without a token type fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(include_token_type=False))

    def test_create_empty_token_type_fails(self):
        """
        Tests that submitting a create request with an empty token type fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(token_type=None))

    def test_create_invalid_token_type_fails(self):
        """
        Tests that submitting a create request with an invalid token type fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(token_type="FOOBAR"))

    def test_create_assigns_correct_token_type(self):
        """
        Tests that submitting a create request assigns the correct value to token type.
        :return: None
        """
        self.send_create_request(token_type="stripe")
        token = self.get_last_created_payment_token()
        self.assertEqual(token.token_type, "stripe")

    def test_create_no_token_value_fails(self):
        """
        Tests that submitting a create request with no token value fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(include_token_value=False))

    def test_create_empty_token_value_fails(self):
        """
        Tests that submitting a create request with an empty token value fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(token_value=None))

    def test_create_invalid_token_value_fails(self):
        """
        Tests that submitting a create request with an invalid token value fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(token_value="ASD!@#"))

    def test_create_assigns_correct_token_value(self):
        """
        Tests that submitting a create request assigns the correct value to token value.
        :return: None
        """
        self.send_create_request(token_value="tok_19xg6sE6xi5DHYsI80fJIOYY")
        token = self.get_last_created_payment_token()
        self.assertEqual(token.token_value, "tok_19xg6sE6xi5DHYsI80fJIOYY")

    def test_create_assigns_correct_card_type(self):
        """
        Tests that submitting a create request assigns the correct value to card type.
        :return: None
        """
        self.send_create_request(card_type="American Express")
        token = self.get_last_created_payment_token()
        self.assertEqual(token.card_type, "American Express")

    def test_create_no_exp_month_fails(self):
        """
        Tests that submitting a create request with no expiration month fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(include_expiration_month=False))

    def test_create_empty_exp_month_fails(self):
        """
        Tests that submitting a create request with an empty expiration month fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(expiration_month=None))

    def test_create_invalid_exp_month_fails(self):
        """
        Tests that submitting a create request with an invalid expiration month fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(expiration_month="ASD!@#"))

    def test_create_too_low_exp_month_fails(self):
        """
        Tests that submitting a create request with a too small value for expiration month fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(expiration_month=0))

    def test_create_too_high_exp_month_fails(self):
        """
        Tests that submitting a create request with a too large value for expiration month fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(expiration_month=13))

    def test_create_assigns_correct_exp_month(self):
        """
        Tests that submitting a create request assigns the correct value to expiration month.
        :return: None
        """
        self.send_create_request(expiration_month=1)
        token = self.get_last_created_payment_token()
        self.assertEqual(token.expiration_month, 1)

    def test_create_no_exp_year_fails(self):
        """
        Tests that submitting a create request with no expiration year fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(include_expiration_year=False))

    def test_create_empty_exp_year_fails(self):
        """
        Tests that submitting a create request with an empty expiration year fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(expiration_year=None))

    def test_create_invalid_exp_year_fails(self):
        """
        Tests that submitting a create request with an invalid expiration year fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(expiration_year="ASD!@#"))

    def test_create_too_low_exp_year_fails(self):
        """
        Tests that submitting a create request with too low of a value for expiration year fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(expiration_year=1999))

    def test_create_too_high_exp_year_fails(self):
        """
        Tests that submitting a create request with too high of a value for expiration year fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(expiration_year=3000))

    def test_create_assigns_correct_exp_year(self):
        """
        Tests that submitting a create request assigns the correct value to expiration year.
        :return: None
        """
        self.send_create_request(expiration_year=2020)
        token = self.get_last_created_payment_token()
        self.assertEqual(token.expiration_year, 2020)

    def test_create_no_card_last_four_fails(self):
        """
        Tests that submitting a create request with no last four fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(include_card_last_four=False))

    def test_create_empty_card_last_four_fails(self):
        """
        Tests that submitting a create request with empty last four fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(card_last_four=None))

    def test_create_invalid_card_last_four_fails(self):
        """
        Tests that submitting a create request with an invalid last four fails.
        :return: None
        """
        self.assert_request_fails(self.send_create_request(card_last_four="ASD!@#"))

    def test_create_assigns_correct_last_four(self):
        """
        Tests that submitting a create request assigns the correct value to last four.
        :return: None
        """
        self.send_create_request(card_last_four="1234")
        token = self.get_last_created_payment_token()
        self.assertEqual(token.card_last_four, "1234")

    @property
    def custom_fields_field(self):
        return "uuid"

    @property
    def custom_fields_method(self):
        return self.__send_list_request

    @property
    def create_method(self):
        return self.__send_create_request

    @property
    def created_object_class(self):
        import rest.models
        return rest.models.PaymentToken

    @property
    def list_method(self):
        return self.__send_list_request

    @property
    def presentation_method(self):
        return self.__send_list_request

    @property
    def response_has_many(self):
        return True


class TestPaymentTokenDetailView(
    RetrieveTestCaseMixin,
    DeleteTestCaseMixin,
    PresentableTestCaseMixin,
    CustomFieldsMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the TestPaymentTokenDetailView APIView.
    """

    _api_route = "/payment-tokens/%s/"
    _url_parameters = None

    def __send_delete_request(self, input_uuid=None, user="user_1", login=True, query_string=None):
        """
        Send a delete request to the API endpoint and return the response.
        :param input_uuid: The UUID of the payment token to delete.
        :param user: The user to send the request on behalf of.
        :param login: Whether or not to log the user in prior to sending the request.
        :param query_string: The query string to submit alongside the URL.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        self._url_parameters = str(input_uuid)
        return self.delete(query_string=query_string)

    def __send_retrieve_request(self, input_uuid="POPULATE", user="user_1", login=True, query_string=None):
        """
        Send a retrieve request to the API endpoint and return the response.
        :param input_uuid: The UUID of the payment token to retrieve.
        :param user: The user to send the request on behalf of.
        :param login: Whether or not to log the user in prior to sending the request.
        :param query_string: The query string to submit alongside the URL.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            token = self.get_payment_token_for_user(user=user)
            input_uuid = token.uuid
        self._url_parameters = str(input_uuid)
        return self.get(query_string=query_string)

    def create_delete_object_for_user(self, user="user_1"):
        user = self.get_user(user=user)
        return user.payment_tokens.create(**WsFaker.get_payment_token_kwargs())

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
        return rest.models.PaymentToken

    @property
    def presentation_method(self):
        return self.__send_retrieve_request

    @property
    def response_has_many(self):
        return False

    @property
    def retrieved_object_class(self):
        return rest.models.PaymentToken

    @property
    def retrieve_method(self):
        return self.__send_retrieve_request
