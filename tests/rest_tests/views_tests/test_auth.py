# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework.authtoken.models import Token

from ..base import WsDjangoViewTestCase


class TestLogoutView(WsDjangoViewTestCase):
    """
    This is a test case class for testing the LogoutView APIView.
    """

    _api_route = "/log-out/"

    def test_get_no_auth_status(self):
        """
        Test to ensure that issuing a GET request to this endpoint while unauthenticated
        returns the expected HTTP status code.
        :return: None
        """
        response = self.get()
        self.assertEqual(response.status_code, 401)

    def test_get_status(self):
        """
        Test to ensure that issuing a GET request to this endpoint while authenticated returns
        the expected HTTP status code.
        :return: None
        """
        self.login()
        response = self.get()
        self.assertEqual(response.status_code, 200)

    def test_get_response_body(self):
        """
        Tests to ensure that the response body from a successful logout request is empty.
        :return: None
        """
        self.login()
        response = self.get()
        self.assertEqual(response.content, "")

    def test_get_deletes_auth_token(self):
        """
        Test to ensure that issuing a GET request to this endpoint while authenticated correctly
        deletes the authorization token from the requesting user.
        :return: None
        """
        self.login()
        initial_count = Token.objects.count()
        self.get()
        second_count = Token.objects.count()
        self.assertEqual(initial_count - 1, second_count)

    def test_get_status_regular_user(self):
        """
        Test to ensure that issuing a GET request to this endpoint while authenticated as a regular user
        returns the expected HTTP status code.
        :return: None
        """
        self.login(user="user_1")
        response = self.get()
        self.assertEqual(response.status_code, 200)

    def test_get_status_admin_user(self):
        """
        Test to ensure that issuing a GET request to this endpoint while authenticated as an administrative
        user returns the expected HTTP status code.
        :return: None
        """
        self.login(user="admin_1")
        response = self.get()
        self.assertEqual(response.status_code, 200)


class TestWsObtainAuthToken(WsDjangoViewTestCase):
    """
    This is a test case class for testing the WsObtainAuthToken APIView.
    """

    _api_route = "/api-token-auth/"

    def __send_login_request(
            self,
            user="user_1",
            include_username=True,
            include_password=True,
            username=None,
            password=None,
    ):
        """
        Submit a login request to the remote endpoint as the given user.
        :param user: A string representing the user to log in as.
        :param include_username: Whether or not to include username in the request body.
        :param include_password: Whether or not to include password in the request body.
        :return: The API response.
        """
        user_data = self.get_user_data(user=user)
        to_send = {}
        if include_username:
            to_send["username"] = username if username is not None else user_data["username"]
        if include_password:
            to_send["password"] = password if password is not None else user_data["password"]
        return self.post(data=to_send)

    def test_post_no_args_status(self):
        """
        Tests to ensure that submitting a login request with no arguments returns the expected
        status code.
        :return: None
        """
        response = self.__send_login_request(include_username=False, include_password=False)
        self.assertEqual(response.status_code, 400)

    def test_post_no_username_status(self):
        """
        Tests to ensure that submitting a login request with no username argument returns the expected
        status code.
        :return: None
        """
        response = self.__send_login_request(include_username=False)
        self.assertEqual(response.status_code, 400)

    def test_post_empty_username_status(self):
        """
        Tests to ensure that submitting a login request with an empty username argument returns the
        expected status code.
        :return: None
        """
        response = self.__send_login_request(username="")
        self.assertEqual(response.status_code, 400)

    def test_post_no_password_status(self):
        """
        Tests to ensure that submitting a login request with no password argument returns the expected
        status code.
        :return: None
        """
        response = self.__send_login_request(include_password=False)
        self.assertEqual(response.status_code, 400)

    def test_post_empty_password_status(self):
        """
        Tests to ensure that submitting a login request with an empty password argument returns the
        expected status code.
        :return: None
        """
        response = self.__send_login_request(password="")
        self.assertEqual(response.status_code, 400)

    def test_post_regular_user_status(self):
        """
        Tests to ensure that submitting a valid login request as a regular user returns the expected
        status code.
        :return: None
        """
        response = self.__send_login_request(user="user_1")
        self.assertEqual(response.status_code, 200)

    def test_post_admin_user_status(self):
        """
        Tests to ensure that submitting a valid login request as an admin user returns the expected
        status code.
        :return: None
        """
        response = self.__send_login_request(user="admin_1")
        self.assertEqual(response.status_code, 200)

    def test_post_response_contains_key(self):
        """
        Tests to ensure that submitting a valid login request returns a response that contains the
        authorization key.
        :return: None
        """
        response = self.__send_login_request()
        self.assertIn("token", response.json())

    def test_post_response_contains_is_admin(self):
        """
        Tests to ensure that submitting a valid login request returns a response that contains a
        boolean is_admin value.
        :return: None
        """
        response = self.__send_login_request()
        self.assertIn("is_admin", response.json())

    def test_post_response_regular_status(self):
        """
        Tests to ensure that submitting a valid login request as a regular user correctly returns
        False for is_admin.
        :return: None
        """
        response = self.__send_login_request(user="user_1")
        self.assertFalse(response.json()["is_admin"])

    def test_post_response_admin_status(self):
        """
        Tests to ensure that submitting a valid login request as an admin user correctly returns True
        for is_admin.
        :return: None
        """
        response = self.__send_login_request(user="admin_1")
        self.assertTrue(response.json()["is_admin"])

    def test_post_unverified_email_status(self):
        """
        Tests to ensure that submitting a valid login request for an account that has not had its
        email verified returns the expected status code.
        :return: None
        """
        user = self.get_user(user="user_1")
        user.email_verified = False
        user.save()
        response = self.__send_login_request(user="user_1")
        user.email_verified = True
        user.save()
        self.assertEqual(response.status_code, 400)

    def test_post_unverified_email_no_token(self):
        """
        Tests to ensure that submitting a valid login request for an account that has not had its
        email verified does not return an authorization token.
        :return: None
        """
        user = self.get_user(user="user_1")
        user.email_verified = False
        user.save()
        response = self.__send_login_request(user="user_1")
        user.email_verified = True
        user.save()
        self.assertNotIn("token", response.json())

    def test_post_not_active_status(self):
        """
        Tests to ensure that submitting a valid login request for an account that has not been activated
        returns the expected status code.
        :return: None
        """
        user = self.get_user(user="user_1")
        user.is_active = False
        user.save()
        response = self.__send_login_request(user="user_1")
        user.is_active = True
        user.save()
        self.assertEqual(response.status_code, 400)

    def test_post_not_active_no_token(self):
        """
        Tests to ensure that submitting a valid login request for an account that has not been activated
        does not return an authorization token.
        :return: None
        """
        user = self.get_user(user="user_1")
        user.is_active = False
        user.save()
        response = self.__send_login_request(user="user_1")
        user.is_active = True
        user.save()
        self.assertNotIn("token", response.json())

    def test_post_regular_user_no_users(self):
        """
        Tests to ensure that a successful login request submitted by a regular user does not return a
        list of users in the response.
        :return: None
        """
        response = self.__send_login_request(user="user_1")
        self.assertNotIn("users", response.json())

    def test_post_admin_user_no_users(self):
        """
        Tests to ensure that a successful login request submitted by an admin user does not return a
        list of users in the response.
        :return: None
        """
        response = self.__send_login_request(user="admin_1")
        self.assertNotIn("users", response.json())


class TestWsCheckAuthTokenStatus(WsDjangoViewTestCase):
    """
    This is a test case class for testing the WsCheckAuthTokenStatus APIView.
    """

    _api_route = "/api-check-token-auth/"

    def test_get_unauthenticated_status(self):
        """
        Test to ensure that requesting the endpoint when unauthenticated returns the expected
        status code.
        :return: None
        """
        response = self.get()
        self.assertEqual(response.status_code, 200)

    def test_get_authenticated_status(self):
        """
        Tests to ensure that requesting the endpoint when authenticated returns the expected status
        code.
        :return: None
        """
        self.login(user="user_1")
        response = self.get()
        self.assertEqual(response.status_code, 200)

    def test_get_admin_authenticated_status(self):
        """
        Tests to ensure that requesting the endpoint when authenticated as an administrative user
        returns the expected status code.
        :return: None
        """
        self.login(user="admin_1")
        response = self.get()
        self.assertEqual(response.status_code, 200)

    def test_get_unauthenticated_token(self):
        """
        Tests to ensure that requesting the endpoint as an unauthenticated user returns an empty
        token value.
        :return: None
        """
        response = self.get()
        self.assertIsNone(response.json()["token"])

    def test_get_unauthenticated_is_admin(self):
        """
        Tests to ensure that requesting the endpoint as an unauthenticated user returns a False value
        for is_admin.
        :return: None
        """
        response = self.get()
        self.assertFalse(response.json()["is_admin"])

    def test_get_unauthenticated_is_authenticated(self):
        """
        Tests to ensure that requesting the endpoint as an unauthenticated user returns a False value
        for is_authenticated.
        :return: None
        """
        response = self.get()
        self.assertFalse(response.json()["is_authenticated"])

    def test_get_regular_token(self):
        """
        Tests to ensure that requesting the endpoint as a regular user returns the expected token value.
        :return: None
        """
        self.login(user="user_1")
        response = self.get()
        auth_token = self.get_auth_token_from_response(response)
        self.assertEqual(auth_token, response.json()["token"])

    def test_get_regular_is_admin(self):
        """
        Tests to ensure that requesting the endpoint as a regular user returns a False value for is_admin.
        :return: None
        """
        self.login(user="user_1")
        response = self.get()
        self.assertFalse(response.json()["is_admin"])

    def test_get_regular_is_authenticated(self):
        """
        Tests to ensure that requesting the endpoint as a regular user returns True for is_authenticated.
        :return: None
        """
        self.login(user="user_1")
        response = self.get()
        self.assertTrue(response.json()["is_authenticated"])

    def test_get_admin_token(self):
        """
        Tests to ensure that requesting the endpoint as an admin user returns the expected token value.
        :return: None
        """
        self.login(user="admin_1")
        response = self.get()
        auth_token = self.get_auth_token_from_response(response)
        self.assertEqual(auth_token, response.json()["token"])

    def test_get_admin_is_admin(self):
        """
        Tests to ensure that requesting the endpoint as an admin user returns the expected is_admin value.
        :return: None
        """
        self.login(user="admin_1")
        response = self.get()
        self.assertTrue(response.json()["is_admin"])

    def test_get_admin_is_authenticated(self):
        """
        Tests to ensure that requesting the endpoint as an admin user returns the expected is_authenticated
        value.
        :return: None
        """
        self.login(user="admin_1")
        response = self.get()
        self.assertTrue(response.json()["is_authenticated"])
