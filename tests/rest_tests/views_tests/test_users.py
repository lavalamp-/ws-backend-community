# -*- coding: utf-8 -*-
from __future__ import absolute_import

from datetime import timedelta
from django.utils import timezone
from mock import MagicMock
from django.contrib.auth import authenticate
from uuid import uuid4

from tasknode.tasks import send_emails_for_user_signup
from ..base import WsDjangoViewTestCase
from ...data import WsTestData
from lib import RandomHelper
from lib.smtp import SmtpEmailHelper
from rest.models import WsUser


class TestUserCreateView(WsDjangoViewTestCase):
    """
    This is a test case for testing the UserCreateView APIView.
    """

    _api_route = "/users/"
    _original_email_delay_method = None

    def setUp(self):
        """
        Set up this test case to mock out the SMTP delay call.
        :return: None
        """
        super(TestUserCreateView, self).setUp()
        self._original_email_delay_method = send_emails_for_user_signup.delay
        send_emails_for_user_signup.delay = MagicMock()

    def tearDown(self):
        """
        Tear down this test case by un-doing mocked out methods.
        :return: None
        """
        send_emails_for_user_signup.delay = self._original_email_delay_method
        super(TestUserCreateView, self).tearDown()

    def __send_create_user_request(
            self,
            include_username=True,
            username=None,
            include_password=True,
            password=None,
            include_first_name=True,
            first_name=None,
            include_last_name=True,
            last_name=None,
    ):
        """
        Send a user creation request to the remote endpoint and return the response.
        :param include_username: Whether or not to include the username in the request.
        :param username: The username to submit in the request.
        :param include_password: Whether or not to include the password in the request.
        :param password: The password to submit in the request.
        :param include_first_name: Whether or not to include the first name in the request.
        :param first_name: The first name to submit in the request.
        :param include_last_name: Whether or not to include the last name in the request.
        :param last_name: The last name to submit in the request.
        :return: The response.
        """
        user_data = WsTestData.CREATE_USER
        to_send = {}
        if include_username:
            to_send["username"] = username if username is not None else user_data["username"]
        if include_password:
            to_send["password"] = password if password is not None else user_data["password"]
        if include_first_name:
            to_send["first_name"] = first_name if first_name is not None else user_data["first_name"]
        if include_last_name:
            to_send["last_name"] = last_name if last_name is not None else user_data["last_name"]
        return self.post(data=to_send)

    def test_successful_status(self):
        """
        Tests to ensure that a successful sign-up request returns the expected status code.
        :return: None
        """
        response = self.__send_create_user_request()
        self.assertEqual(response.status_code, 201)

    def test_successful_creates_user(self):
        """
        Tests to ensure that a successful sign-up request creates a new User object.
        :return: None
        """
        initial_count = WsUser.objects.count()
        self.__send_create_user_request()
        second_count = WsUser.objects.count()
        self.assertEqual(second_count, initial_count + 1)

    def test_successful_creates_user_username(self):
        """
        Tests to ensure that a successful sign-up request populates the username field of the
        newly-created user object with the expected value.
        :return: None
        """
        self.__send_create_user_request(username="test4@websight.io")
        user = self.get_last_created_user()
        self.assertEqual(user.username, "test4@websight.io")

    def test_successful_creates_user_email(self):
        """
        Tests to ensure that a successful sign-up request populates the email field of the
        newly-created user object with the expected value.
        :return: None
        """
        self.__send_create_user_request(username="test4@websight.io")
        user = self.get_last_created_user()
        self.assertEqual(user.email, "test4@websight.io")
        
    def test_successful_creates_user_first_name(self):
        """
        Tests to ensure that a successful sign-up request populates the first_name field of the
        newly-created user object with the expected value.
        :return: None
        """
        self.__send_create_user_request(first_name="Barry")
        user = self.get_last_created_user()
        self.assertEqual(user.first_name, "Barry")
        
    def test_successful_creates_user_last_name(self):
        """
        Tests to ensure that a successful sign-up request populates the last_name field of the
        newly-created user object with the expected value.
        :return: None
        """
        self.__send_create_user_request(last_name="Bonds")
        user = self.get_last_created_user()
        self.assertEqual(user.last_name, "Bonds")
        
    def test_successful_creates_user_password(self):
        """
        Tests to ensure that a successful sign-up request populates the password field of the
        newly-created user object with the expected value.
        :return: None
        """
        self.__send_create_user_request(password="P@ssw0rd123!", username="test4@websight.io")
        result = authenticate(username="test4@websight.io", password="P@ssw0rd123!")
        self.assertTrue(result)

    def test_successful_creates_user_email_verified(self):
        """
        Tests to ensure that a successful sign-up requests sets the expected value for the email_verified
        attribute on the newly-created user.
        :return: None
        """
        self.__send_create_user_request()
        user = self.get_last_created_user()
        self.assertFalse(user.email_verified)

    def test_successful_creates_user_approved(self):
        """
        Tests to ensure that a successful sign-up request sets the expected value for the account_manually_approved
        attribute on the newly-created user.
        :return: None
        """
        self.__send_create_user_request()
        user = self.get_last_created_user()
        self.assertFalse(user.account_manually_approved)

    def test_successful_creates_user_is_superuser(self):
        """
        Tests to ensure that a successful sign-up request sets the expected value for the is_superuser
        attribute on the newly-created user.
        :return: None
        """
        self.__send_create_user_request()
        user = self.get_last_created_user()
        self.assertFalse(user.is_superuser)

    def test_successful_calls_smtp_helper_send_verification(self):
        """
        Tests to ensure that a successful sign-up requests calls SmtpEmailHelper.send_verification_email.
        :return: None
        """
        self.__send_create_user_request()
        self.assertTrue(send_emails_for_user_signup.delay.called)

    def test_no_username_fails(self):
        """
        Tests to ensure that a sign-up request that does not contain a username fails.
        :return: None
        """
        response = self.__send_create_user_request(include_username=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_username_fails(self):
        """
        Tests to ensure that a sign-up request containing an empty username fails.
        :return: None
        """
        response = self.__send_create_user_request(username="")
        self.assertEqual(response.status_code, 400)

    def test_invalid_username_fails(self):
        """
        Tests to ensure that a sign-up request containing an invalid username fails.
        :return: None
        """
        response = self.__send_create_user_request(username="_")
        self.assertEqual(response.status_code, 400)

    def test_taken_username_fails(self):
        """
        Tests to ensure that a sign-up request containing a username that is already taken fails.
        :return: None
        """
        key = WsTestData.USERS.keys()[0]
        response = self.__send_create_user_request(username=WsTestData.USERS[key]["username"])
        self.assertEqual(response.status_code, 400)

    def test_no_password_fails(self):
        """
        Tests to ensure that a sign-up request that does not contain a password fails.
        :return: None
        """
        response = self.__send_create_user_request(include_password=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_password_fails(self):
        """
        Tests to ensure that a sign-up request that contains an empty password fails.
        :return: None
        """
        response = self.__send_create_user_request(password="")
        self.assertEqual(response.status_code, 400)

    def test_too_short_password_fails(self):
        """
        Tests to ensure that a sign-up request with a password that is too short fails.
        :return: None
        """
        response = self.__send_create_user_request(password="1!wW_as")
        self.assertEqual(response.status_code, 400)

    def test_no_upper_password_fails(self):
        """
        Tests to ensure that a sign-up request with a password that does not include an upper-case
        character fails.
        :return: None
        """
        response = self.__send_create_user_request(password="123!@#asd")
        self.assertEqual(response.status_code, 400)

    def test_no_digit_password_fails(self):
        """
        Tests to ensure that a sign-up request with a password that does not include a number fails.
        :return: None
        """
        response = self.__send_create_user_request(password="!@#ASDasd")
        self.assertEqual(response.status_code, 400)

    def test_no_special_password_fails(self):
        """
        Tests to ensure that a sign-up request with a password that does not include a special character
        fails.
        :return: None
        """
        response = self.__send_create_user_request(password="ASDasd123456")
        self.assertEqual(response.status_code, 400)

    def test_no_first_name_fails(self):
        """
        Tests to ensure that a sign-up request with no first name fails.
        :return: None
        """
        response = self.__send_create_user_request(include_first_name=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_first_name_fails(self):
        """
        Tests to ensure that a sign-up request with an empty first name fails.
        :return: None
        """
        response = self.__send_create_user_request(first_name="")
        self.assertEqual(response.status_code, 400)

    def test_no_last_name_fails(self):
        """
        Tests to ensure that a sign-up request with no last name fails.
        :return: None
        """
        response = self.__send_create_user_request(include_last_name=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_last_name_fails(self):
        """
        Tests to ensure that a sign-up request with an empty last name fails.
        :return: None
        """
        response = self.__send_create_user_request(last_name="")
        self.assertEqual(response.status_code, 400)


class TestVerifyEmailView(WsDjangoViewTestCase):
    """
    This is a test case for testing the VerifyEmailView APIView.
    """

    _api_route = "/verify-email/"
    _email_token = None
    _user_uuid = None

    def setUp(self):
        """
        Initialize the test case by ensuring that an email verification token is associated
        with user_1.
        :return: None
        """
        super(TestVerifyEmailView, self).setUp()
        user = self.get_user(user="user_1")
        user.email_verified = False
        user.save()
        self._email_token = user.email_registration_code
        self._user_uuid = user.uuid

    def __send_verify_email_request(
            self,
            include_email_token=True,
            email_token=None,
            include_user_uuid=True,
            user_uuid=None,
    ):
        """
        Submit a verify email HTTP request to the remote endpoint and return the response.
        :param include_email_token: Whether or not to include the email token in the request.
        :param email_token: The email token to submit in the request.
        :param include_user_uuid: Whether or not to include the user UUID in the request.
        :param user_uuid: The user UUID to submit in the request.
        :return: The response.
        """
        to_send = {}
        if include_email_token:
            to_send["email_token"] = email_token if email_token is not None else self.email_token
        if include_user_uuid:
            to_send["user_uuid"] = user_uuid if user_uuid is not None else self.user_uuid
        return self.post(data=to_send)

    def test_no_email_token_fails(self):
        """
        Tests to ensure that submitting a verify email request without an email token fails.
        :return: None
        """
        response = self.__send_verify_email_request(include_email_token=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_email_token_fails(self):
        """
        Tests to ensure that submitting a verify email request with an empty email token fails.
        :return: None
        """
        response = self.__send_verify_email_request(email_token="")
        self.assertEqual(response.status_code, 400)

    def test_invalid_email_token_fails(self):
        """
        Tests to ensure that submitting a verify email request with an invalid email token fails.
        :return: None
        """
        response = self.__send_verify_email_request(email_token="asd123asd123")
        self.assertEqual(response.status_code, 400)

    def test_unknown_email_token_fails(self):
        """
        Tests to ensure that submitting a verify email request with an unknown email token fails.
        :return: None
        """
        response = self.__send_verify_email_request(email_token=str(uuid4()))
        self.assertEqual(response.status_code, 400)

    def test_no_user_uuid_fails(self):
        """
        Tests to ensure that submitting a verify email request without a user UUID fails.
        :return: None
        """
        response = self.__send_verify_email_request(include_user_uuid=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_user_uuid_fails(self):
        """
        Tests to ensure that submitting a verify email request with an empty user UUID fails.
        :return: None
        """
        response = self.__send_verify_email_request(user_uuid="")
        self.assertEqual(response.status_code, 400)

    def test_invalid_user_uuid_fails(self):
        """
        Tests to ensure that submitting a verify email request with an invalid user UUID fails.
        :return: None
        """
        response = self.__send_verify_email_request(user_uuid="asd123asd123")
        self.assertEqual(response.status_code, 400)

    def test_unknown_user_uuid_fails(self):
        """
        Tests to ensure that submitting a verify email request with an unknown user UUID fails.
        :return: None
        """
        response = self.__send_verify_email_request(user_uuid=str(uuid4()))
        self.assertEqual(response.status_code, 404)

    def test_success_status(self):
        """
        Tests to ensure that submitting a successful verify email request returns the expected status
        code.
        :return: None
        """
        response = self.__send_verify_email_request()
        self.assertEqual(response.status_code, 200)

    def test_success_email_verified(self):
        """
        Tests to ensure that submitting a successful verify email request updates the affected user to
        show that their email has been verified.
        :return: None
        """
        self.__send_verify_email_request()
        user = self.get_user(user="user_1")
        self.assertTrue(user.email_verified)

    @property
    def email_token(self):
        """
        Get the email token associated with user_1.
        :return: the email token associated with user_1.
        """
        return self._email_token

    @property
    def user_uuid(self):
        """
        Get the user UUID to submit alongside requests.
        :return: the user UUID to submit alongside requests.
        """
        return self._user_uuid


class TestSetupAccountView(WsDjangoViewTestCase):
    """
    This is a test case for testing the SetupAccountView APIView.
    """

    _api_route = "/setup-account/"
    _email_token = None
    _user_uuid = None

    def setUp(self):
        """
        Set up all of the unit tests for this test case by ensuring that user_1 has not
        yet been activated and by populating the fields necessary for submission.
        :return: None
        """
        super(TestSetupAccountView, self).setUp()
        user = self.get_user(user="user_1")
        self._email_token = user.email_registration_code
        self._user_uuid = user.uuid
        user.email_verified = False
        user.save()

    def __send_setup_account_request(
            self,
            include_email_token=True,
            email_token=None,
            include_user_uuid=True,
            user_uuid=None,
            include_first_name=True,
            first_name=None,
            include_last_name=True,
            last_name=None,
            include_password=True,
            password=None,
    ):
        """
        Send a setup account request to the API endpoint and return the response.
        :param include_email_token: Whether or not to include the email token in the request.
        :param email_token: The email token to include.
        :param include_user_uuid: Whether or not to include the user UUID in the request.
        :param user_uuid: The user UUID to include.
        :param include_first_name: Whether or not to include the user first name in the request.
        :param first_name: The first name to include in the request.
        :param include_last_name: Whether or not to include the last name in the request.
        :param last_name: The last name to include in the request.
        :param include_password: Whether or not to include the password in the request.
        :param password: The password to include the in request.
        :return: The API response.
        """
        to_send = {}
        user_data = self.get_user_data(user="user_1")
        if include_email_token:
            to_send["email_token"] = email_token if email_token is not None else self.email_token
        if include_user_uuid:
            to_send["user_uuid"] = user_uuid if user_uuid is not None else self.user_uuid
        if include_first_name:
            to_send["first_name"] = first_name if first_name is not None else user_data["first_name"]
        if include_last_name:
            to_send["last_name"] = last_name if last_name is not None else user_data["last_name"]
        if include_password:
            to_send["password"] = password if password is not None else user_data["password"]
        return self.post(data=to_send)

    def test_success_status(self):
        """
        Tests to ensure that a successful setup account request returns the expected status code.
        :return: None
        """
        response = self.send()
        self.assertEqual(response.status_code, 200)

    def test_success_response_body(self):
        """
        Tests to ensure that a successful setup account request returns a response with an empty
        body.
        :return: None
        """
        response = self.send()
        self.assertEqual(response.content, "")

    def test_success_sets_first_name(self):
        """
        Tests to ensure that a successful request sets the proper value for the user's first name.
        :return: None
        """
        self.send(first_name="foobarbaz")
        user = self.get_user(user="user_1")
        self.assertEqual(user.first_name, "foobarbaz")

    def test_success_sets_last_name(self):
        """
        Tests to ensure that a successful request sets the proper value for the user's last name.
        :return: None
        """
        self.send(last_name="foobarbaz")
        user = self.get_user(user="user_1")
        self.assertEqual(user.last_name, "foobarbaz")

    def test_success_email_verified(self):
        """
        Tests to ensure that a successful request sets the user's account as having had its email
        verified.
        :return: None
        """
        self.send()
        user = self.get_user(user="user_1")
        self.assertTrue(user.email_verified)

    def test_success_sets_password(self):
        """
        Tests to ensure that a successful request sets the user's password to the expected value.
        :return: None
        """
        self.send(password="P@ssw0rd123!!")
        user_data = self.get_user_data(user="user_1")
        auth_check = authenticate(username=user_data["username"], password="P@ssw0rd123!!")
        self.assertTrue(auth_check)

    def test_no_email_token_fails(self):
        """
        Tests to ensure that a request that does not contain an email token fails.
        :return: None
        """
        response = self.send(include_email_token=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_email_token_fails(self):
        """
        Tests to ensure that a request that contains an empty email token fails.
        :return: None
        """
        response = self.send(email_token="")
        self.assertEqual(response.status_code, 400)

    def test_invalid_email_token_fails(self):
        """
        Tests to ensure that a request that contains an invalid email token fails.
        :return: None
        """
        response = self.send(email_token="asd123asd123")
        self.assertEqual(response.status_code, 400)

    def test_unknown_email_token_fails(self):
        """
        Tests to ensure that a request that contains an unknown email token fails.
        :return: None
        """
        response = self.send(email_token=str(uuid4()))
        self.assertEqual(response.status_code, 400)

    def test_no_user_uuid_fails(self):
        """
        Tests to ensure that a request that does not contain a user UUID fails.
        :return: None
        """
        response = self.send(include_user_uuid=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_user_uuid_fails(self):
        """
        Tests to ensure that a request that contains an empty user UUID fails.
        :return: None
        """
        response = self.send(user_uuid="")
        self.assertEqual(response.status_code, 400)

    def test_invalid_user_uuid_fails(self):
        """
        Tests to ensure that a request with an invalid user UUID fails.
        :return: None
        """
        response = self.send(user_uuid="asd123asd123")
        self.assertEqual(response.status_code, 400)

    def test_unknown_user_uuid_fails(self):
        """
        Tests to ensure that a request with an unknown user UUID fails.
        :return: None
        """
        response = self.send(user_uuid=str(uuid4()))
        self.assertEqual(response.status_code, 404)

    def test_no_first_name_fails(self):
        """
        Tests to ensure that a request that does not contain a first name fails.
        :return: None
        """
        response = self.send(include_first_name=False)
        self.assertEqual(response.status_code, 400)
        
    def test_empty_first_name_fails(self):
        """
        Tests to ensure that a request that contains an empty first name fails.
        :return: None
        """
        response = self.send(first_name="")
        self.assertEqual(response.status_code, 400)
        
    def test_no_last_name_fails(self):
        """
        Tests to ensure that a request that does not contain a last name fails.
        :return: None
        """
        response = self.send(include_last_name=False)
        self.assertEqual(response.status_code, 400)
        
    def test_empty_last_name_fails(self):
        """
        Tests to ensure that a request that contains an empty last name fails.
        :return: None
        """
        response = self.send(last_name="")
        self.assertEqual(response.status_code, 400)
        
    def test_no_password_fails(self):
        """
        Tests to ensure that a request that does not contain a password fails.
        :return: None
        """
        response = self.send(include_password=False)
        self.assertEqual(response.status_code, 400)
        
    def test_empty_password_fails(self):
        """
        Tests to ensure that a request that contains an empty password fails.
        :return: None
        """
        response = self.send(password="")
        self.assertEqual(response.status_code, 400)

    def test_too_short_password_fails(self):
        """
        Tests to ensure that a sign-up request with a password that is too short fails.
        :return: None
        """
        response = self.send(password="1!wW_as")
        self.assertEqual(response.status_code, 400)

    def test_no_upper_password_fails(self):
        """
        Tests to ensure that a request with a password that does not include an upper-case
        character fails.
        :return: None
        """
        response = self.send(password="123!@#asd")
        self.assertEqual(response.status_code, 400)

    def test_no_digit_password_fails(self):
        """
        Tests to ensure that a request with a password that does not include a number fails.
        :return: None
        """
        response = self.send(password="!@#ASDasd")
        self.assertEqual(response.status_code, 400)

    def test_no_special_password_fails(self):
        """
        Tests to ensure that a request with a password that does not include a special character
        fails.
        :return: None
        """
        response = self.send(password="ASDasd123456")
        self.assertEqual(response.status_code, 400)

    @property
    def email_token(self):
        """
        Get the email token associated with user_1.
        :return: the email token associated with user_1.
        """
        return self._email_token

    @property
    def send_method(self):
        return self.__send_setup_account_request

    @property
    def user_uuid(self):
        """
        Get the user UUID to submit alongside requests.
        :return: the user UUID to submit alongside requests.
        """
        return self._user_uuid


class TestForgotPasswordView(WsDjangoViewTestCase):
    """
    This is a test case for testing the ForgotPasswordView APIView.
    """

    _api_route = "/forgot-password/"

    def __send_forgot_password_request(self, include_email_address=True, email_address=None):
        """
        Send a forgot password request to the server.
        :param include_email_address: Whether or not to include the email address field in the request.
        :param email_address: The email address to include.
        :return: The response.
        """
        to_send = {}
        user = self.get_user(user="user_1")
        if include_email_address:
            to_send["email_address"] = email_address if email_address is not None else user.email
        smtp_helper = SmtpEmailHelper.instance()
        smtp_helper.send_forgot_password_email = MagicMock()
        user.forgot_password_code = None
        user.forgot_password_date = None
        user.save()
        return self.post(data=to_send)

    def test_success_status(self):
        """
        Tests to ensure that a successful request returns the expected status code.
        :return: None
        """
        response = self.send()
        self.assertEqual(response.status_code, 200)

    def test_success_populated_forgot_password_code(self):
        """
        Tests to ensure that a successful request populates the forgot_password_code attribute on
        the affected user.
        :return: None
        """
        self.send()
        user = self.get_user(user="user_1")
        self.assertIsNotNone(user.forgot_password_code)

    def test_success_populates_forgot_password_date(self):
        """
        Tests to ensure that a successful request populates the forgot_password_date attribute on the
        affected user.
        :return: None
        """
        self.send()
        user = self.get_user(user="user_1")
        self.assertIsNotNone(user.forgot_password_date)

    def test_success_calls_send_email(self):
        """
        Tests to ensure that a successful request calls send_forgot_password_email.
        :return: None
        """
        self.send()
        smtp_helper = SmtpEmailHelper.instance()
        self.assertTrue(smtp_helper.send_forgot_password_email.called)

    def test_success_empty_response(self):
        """
        Tests to ensure that a successful request returns a response with an empty body.
        :return: None
        """
        response = self.send()
        self.assertEqual(response.content, "")

    def test_no_email_fails(self):
        """
        Tests to ensure that a request that does not contain an email address fails.
        :return: None
        """
        response = self.send(include_email_address=False)
        self.assertEqual(response.status_code, 400)

    def test_unknown_email_fails(self):
        """
        Tests to ensure that a request that contains an unknown email address fails.
        :return: None
        """
        response = self.send(email_address="foobar@foo.bar.com")
        self.assertEqual(response.status_code, 404)

    @property
    def send_method(self):
        return self.__send_forgot_password_request


class TestVerifyForgotPasswordView(WsDjangoViewTestCase):
    """
    This is a test case for testing the VerifyForgotPasswordView APIView.
    """

    _api_route = "/verify-forgot-password/"
    _email_token = None

    def setUp(self):
        """
        Set up this test case so that user_1 has a forgot password token associated with their
        user.
        :return: None
        """
        super(TestVerifyForgotPasswordView, self).setUp()
        user = self.get_user(user="user_1")
        user.forgot_password_code = RandomHelper.get_cryptographic_uuid()
        user.forgot_password_date = timezone.now()
        self._email_token = user.forgot_password_code
        user.save()

    def __send_verify_forgot_password_request(
            self,
            include_email_token=True,
            email_token=None,
            include_user_uuid=True,
            user_uuid=None,
            include_new_password=True,
            password=None,
            reset_time_ago=None,
    ):
        """
        Submit a verify forgot password request to the API.
        :param include_email_token: Whether or not to include the email token in the request.
        :param email_token: The email token to include in the request.
        :param include_user_uuid: Whether or not to include the user UUID in the request.
        :param user_uuid: The user UUID to include in the request.
        :param include_new_password: Whether or not to include the new password in the request.
        :param password: The password to include in the request.
        :param reset_time_ago: The amount of time (in seconds) ago that the user submitted their
        forgot password request.
        :return: The response.
        """
        to_send = {}
        user_data = self.get_user_data(user="user_1")
        user = self.get_user(user="user_1")
        if include_email_token:
            to_send["email_token"] = email_token if email_token is not None else self.email_token
        if include_user_uuid:
            to_send["user_uuid"] = user_uuid if user_uuid is not None else user.uuid
        if include_new_password:
            to_send["new_password"] = password if password is not None else user_data["password"] + "!!"
        if reset_time_ago is not None:
            user.forgot_password_date = user.forgot_password_date - timedelta(seconds=reset_time_ago)
            user.save()
        return self.post(data=to_send)

    def test_success_status(self):
        """
        Tests to ensure that a successful request returns the expected status code.
        :return: None
        """
        response = self.send()
        self.assertEqual(response.status_code, 200)

    def test_success_sets_password(self):
        """
        Tests to ensure that a successful requests sets the user's password to the expected value.
        :return: None
        """
        self.send(password="P@ssw0rd09123!!#")
        user_data = self.get_user_data(user="user_1")
        auth_check = authenticate(username=user_data["username"], password="P@ssw0rd09123!!#")
        self.assertTrue(auth_check)

    def test_success_removes_forgot_code(self):
        """
        Tests to ensure that a successful request removes the forgot password code from the
        affected user.
        :return: None
        """
        self.send()
        user = self.get_user(user="user_1")
        self.assertIsNone(user.forgot_password_code)

    def test_success_empty_response(self):
        """
        Tests to ensure that a successful request returns a response with an empty body.
        :return: None
        """
        response = self.send()
        self.assertEqual(response.content, "")

    def test_no_email_token_fails(self):
        """
        Tests to ensure that a request that does not contain an email token fails.
        :return: None
        """
        response = self.send(include_email_token=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_email_token_fails(self):
        """
        Tests to ensure that a request that contains an empty email token fails.
        :return: None
        """
        response = self.send(email_token="")
        self.assertEqual(response.status_code, 400)

    def test_invalid_email_token_fails(self):
        """
        Tests to ensure that a request that contains an invalid email token fails.
        :return: None
        """
        response = self.send(email_token="asd123asd123")
        self.assertEqual(response.status_code, 400)

    def test_unknown_email_token_fails(self):
        """
        Tests to ensure that a request that contains an unknown email token fails.
        :return: None
        """
        response = self.send(email_token=str(uuid4()))
        self.assertEqual(response.status_code, 400)

    def test_no_user_uuid_fails(self):
        """
        Tests to ensure that a request that does not contain a user UUID fails.
        :return: None
        """
        response = self.send(include_user_uuid=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_user_uuid_fails(self):
        """
        Tests to ensure that a request that contains an empty user UUID fails.
        :return: None
        """
        response = self.send(user_uuid="")
        self.assertEqual(response.status_code, 400)

    def test_invalid_user_uuid_fails(self):
        """
        Tests to ensure that a request that contains an invalid user UUID fails.
        :return: None
        """
        response = self.send(user_uuid="asd123asd123")
        self.assertEqual(response.status_code, 400)

    def test_unknown_user_uuid_fails(self):
        """
        Tests to ensure that a request that contains an unknown user UUID fails.
        :return: None
        """
        response = self.send(user_uuid=str(uuid4()))
        self.assertEqual(response.status_code, 404)

    def test_no_new_password_fails(self):
        """
        Tests to ensure that a request that does not contain a password fails.
        :return: None
        """
        response = self.send(include_new_password=False)
        self.assertEqual(response.status_code, 400)

    def test_empty_new_password_fails(self):
        """
        Tests to ensure that a request that contains an empty password fails.
        :return: None
        """
        response = self.send(password="")
        self.assertEqual(response.status_code, 400)

    def test_too_short_password_fails(self):
        """
        Tests to ensure that a sign-up request with a password that is too short fails.
        :return: None
        """
        response = self.send(password="1!wW_as")
        self.assertEqual(response.status_code, 400)

    def test_no_upper_password_fails(self):
        """
        Tests to ensure that a request with a password that does not include an upper-case
        character fails.
        :return: None
        """
        response = self.send(password="123!@#asd")
        self.assertEqual(response.status_code, 400)

    def test_no_digit_password_fails(self):
        """
        Tests to ensure that a request with a password that does not include a number fails.
        :return: None
        """
        response = self.send(password="!@#ASDasd")
        self.assertEqual(response.status_code, 400)

    def test_no_special_password_fails(self):
        """
        Tests to ensure that a request with a password that does not include a special character
        fails.
        :return: None
        """
        response = self.send(password="ASDasd123456")
        self.assertEqual(response.status_code, 400)

    def test_too_long_ago_fails(self):
        """
        Tests to ensure that a valid request submitted at a time when the forgot password request
        was submitted too long ago fails.
        :return: None
        """
        response = self.send(reset_time_ago=60*60*24*7)
        self.assertEqual(response.status_code, 400)

    @property
    def email_token(self):
        """
        Get the email token associated with user_1.
        :return: the email token associated with user_1.
        """
        return self._email_token

    @property
    def send_method(self):
        return self.__send_verify_forgot_password_request
