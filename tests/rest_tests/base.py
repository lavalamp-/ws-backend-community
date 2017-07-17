# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.test import TestCase, Client
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from rest.models import WsUser, Organization, Network, DomainName, Order
from ..data import WsTestData
from .mixin import ParameterizedRouteMixin, PaginatedTestCaseMixin


class WsDjangoTestCase(TestCase):
    """
    This is a base class for all test cases used to testing the Web Sight Django API.
    """

    def get_domain_name_for_user(self, user="user_1"):
        """
        Get the domain name to use for testing purposes for the given user.
        :param user: The user to retrieve the domain name for.
        :return: The domain name associated with the given user.
        """
        return self.get_organization_for_user(user=user).domain_names.first()

    def get_last_created(self, model_class):
        """
        Get the most recently-created instance of the given model class from the database.
        :param model_class: The Django model class to get the last created instance of.
        :return: The most recently-created instance of the given model class.
        """
        return model_class.objects.order_by("-created").first()

    def get_last_created_domain_name(self):
        """
        Get the most recently created domain name.
        :return: The most recently created domain name.
        """
        return self.get_last_created(DomainName)

    def get_last_created_network(self):
        """
        Get the most recently created Network.
        :return: The most recently created network.
        """
        return self.get_last_created(Network)

    def get_last_created_order(self):
        """
        Get the most recently-created Order object.
        :return: The most recently-created Order object.
        """
        return self.get_last_created(Order)

    def get_last_created_organization(self):
        """
        Get the most recently created Organization object.
        :return: The most recently created Organization object.
        """
        return self.get_last_created(Organization)

    def get_last_created_user(self):
        """
        Get the most recently-created WsUser object.
        :return: The most recently-created WsUser object.
        """
        return self.get_last_created(WsUser)

    def get_ip_address_for_user(self, user="user_1"):
        """
        Get the IP address to use for testing purposes for the given user.
        :param user: The user to retrieve the IP address for.
        :return: The IP address associated with the given user.
        """
        return self.get_network_for_user(user=user).ip_addresses.first()

    def get_network_for_user(self, user="user_1"):
        """
        Get the network to use for testing purposes for the given user.
        :param user: The user to retireve the network for.
        :return: The network associated with the given user.
        """
        return self.get_organization_for_user(user=user).networks.first()

    def get_network_service_for_user(self, user="user_1"):
        """
        Get the network service to use for testing purposes for the given user.
        :param user: The user to retrieve the network service for.
        :return: The network service associated with the given user.
        """
        return self.get_ip_address_for_user(user=user).network_services.first()

    def get_object_by_class_for_user(self, user="user_1", object_class=None):
        """
        Get an instance of the given class type owned by the specified user.
        :param user: A string depicting the user to get an instance of the class type for.
        :param object_class: The class of object to retrieve.
        :return: An instance of object_class owned by the given user.
        """
        if object_class == Order:
            return self.get_order_for_user(user=user)
        elif object_class == Organization:
            return self.get_organization_for_user(user=user)
        else:
            raise TypeError(
                "No mapping to retrieve object of type %s for user %s."
                % (object_class.__name__, user)
            )

    def get_order_for_user(self, user="user_1"):
        """
        Get the order to use for testing purposes for the given user.
        :param user: The user to retrieve the order for.
        :return: The order associated with the given user.
        """
        user = self.get_user(user=user)
        return user.orders.first()

    def get_organization_for_user(self, user="user_1"):
        """
        Get the organization to use for testing purposes for the given user.
        :param user: The user to retrieve the organization for.
        :return: The organization associated with the given user.
        """
        user = self.get_user(user=user)
        return user.organizations[0]

    def get_user(self, user="user_1"):
        """
        Get the User object associated with the given string.
        :param user: A string indicating which user to retrieve.
        :return: The user associated with the given string.
        """
        user_data = self.get_user_data(user=user)
        return WsUser.objects.get(username=user_data["username"])

    def get_user_data(self, user="user_1"):
        """
        Get a dictionary containing the keyword arguments supplied to the creation of the given
        user.
        :param user: A string depicting which user dictionary to return.
        :return: A dictionary containing the keyword arguments passed to WsUser.objects.create_user.
        """
        if user == "user_1":
            return WsTestData.TEST_USER_1
        elif user == "user_2":
            return WsTestData.TEST_USER_2
        elif user == "admin_1":
            return WsTestData.ADMIN_USER_1
        else:
            raise ValueError(
                "Not sure how to handle user retrieval for user %s."
                % (user,)
            )

    def get_web_service_for_user(self, user="user_1"):
        """
        Get the web service to use for testing purposes for the given user.
        :param user: The user to retrieve the web service for.
        :return: The web service associated with the given user.
        """
        return self.get_network_service_for_user(user=user).web_services.first()

    def setUp(self):
        """
        Initialize this test case so that the database is fully populated.
        :return: None
        """
        self.client = APIClient()


class WsDjangoViewTestCase(WsDjangoTestCase):
    """
    This is a base class for all test cases used for testing views associated with the Web Sight
    Django API.
    """

    _api_route = None
    _requires_auth = None

    def assert_request_fails(self, response, fail_status=400):
        """
        Assert that the given response failed and has the given status code.
        :param response: The response to check.
        :param fail_status: The status code to check against.
        :return: None
        """
        self.assertEqual(response.status_code, fail_status)

    def assert_request_not_authorized(self, response):
        """
        Assert that the given response failed and returned a 403 not authorized.
        :param response: The response to check.
        :return: None
        """
        self.assertEqual(response.status_code, 403)

    def delete(self, query_string=None, **kwargs):
        """
        Issue an HTTP DELETE request to the remote endpoint with the given keyword
        arguments.
        :param query_string: The query string to submit to add to the api route.
        :param kwargs: Keyword arguments to pass to self.client.delete.
        :return: The response.
        """
        if query_string is not None:
            api_route = "%s?%s" % (self.api_route, query_string)
        else:
            api_route = self.api_route
        return self.client.delete(api_route, **kwargs)

    def get(self, query_string=None, **kwargs):
        """
        Issue an HTTP GET request to the remote endpoint with the given keyword arguments.
        :param query_string: The query string to submit to add to the api route.
        :param kwargs: Keyword arguments to pass to self.client.get.
        :return: The response.
        """
        if query_string is not None:
            api_route = "%s?%s" % (self.api_route, query_string)
        else:
            api_route = self.api_route
        return self.client.get(api_route, **kwargs)

    def get_auth_token_from_response(self, response):
        """
        Parse the authorization token from the given response.
        :param response: The Django response to process.
        :return: The authorization token value associated with the request.
        """
        return response.request["HTTP_AUTHORIZATION"].split(" ")[1]

    def login(self, user="user_1"):
        """
        Log in with the given user.
        :param user: A string describing the user to log in with.
        :return: None
        """
        user_object = self.get_user(user=user)
        token = Token.objects.create(user=user_object)
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def patch(self, query_string=None, *args, **kwargs):
        """
        Issue an HTTP PATCH request to the remote endpoint with the given arguments.
        :param query_string: The query string to submit in the request.
        :param args: Positional arguments to pass to self.client.patch.
        :param kwargs: Keyword arguments to pass to self.client.patch.
        :return: The response.
        """
        if query_string is not None:
            api_route = "%s?%s" % (self.api_route, query_string)
        else:
            api_route = self.api_route
        return self.client.patch(api_route, *args, **kwargs)

    def post(self, query_string=None, *args, **kwargs):
        """
        Issue an HTTP POST request to the remote endpoint with the given keyword arguments.
        :param query_string: The query string to submit to the api route.
        :param args: Positional arguments to pass to self.client.post.
        :param kwargs: Keyword arguments to pass to self.client.post.
        :return: The response.
        """
        if query_string is not None:
            api_route = "%s?%s" % (self.api_route, query_string)
        else:
            api_route = self.api_route
        return self.client.post(api_route, *args, **kwargs)

    def put(self, query_string=None, *args, **kwargs):
        """
        Issue an HTTP PUT request to the remote endpoint with the given keyword arguments.
        :param query_string: The query string to submit to the api route.
        :param args: Positional arguments to pass to self.client.put.
        :param kwargs: Keyword arguments to pass to self.client.put.
        :return: The response.
        """
        if query_string is not None:
            api_route = "%s?%s" % (self.api_route, query_string)
        else:
            api_route = self.api_route
        return self.client.put(api_route, *args, **kwargs)

    def send(self, **kwargs):
        """
        Submit the request to the remote endpoint.
        :param kwargs: Keyword arguments to supply to the method.
        :return: A response.
        """
        return self.send_method(**kwargs)

    @property
    def api_route(self):
        """
        Get the URL route that the view associated with this test case is mounted at.
        :return: the URL route that the view associated with this test case is mounted at.
        """
        return self._api_route

    @property
    def requires_auth(self):
        """
        Get whether or not the API endpoint requires users to be authenticated.
        :return: whether or not the API endpoint requires users to be authenticated.
        """
        return self._requires_auth

    @property
    def send_method(self):
        """
        Get the method that should be invoked to send a request to the API endpoint.
        :return: the method that should be invoked to send a request to the API endpoint.
        """
        raise NotImplementedError("Subclasses must implement this!")
