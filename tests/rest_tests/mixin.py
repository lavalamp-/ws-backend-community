# -*- coding: utf-8 -*-
from __future__ import absolute_import

from uuid import uuid4
from django.conf import settings
from rest_framework.settings import api_settings

from lib import ExcelExporter, CsvExporter
from wsbackend import settings


class ParameterizedRouteMixin(object):
    """
    This is a mixin class that overrides the default api_route property to enable test cases
    to specify URL parameters.
    """

    _url_parameters = None

    @property
    def api_route(self):
        return self._api_route % self.url_parameters

    @property
    def url_parameters(self):
        """
        Get a list of values to pass to string formatting of self._api_route.
        :return: a list of values to pass to string formatting of self._api_route.
        """
        return self._url_parameters


class DefaultViewTestCaseMixin(object):
    """
    This is a mixin class that provides some default unit tests for all APIView classes.
    """

    _success_status = 200

    def test_success_status(self):
        """
        Tests to ensure that a successful request returns the expected status code.
        :return: None
        """
        response = self.send()
        self.assertEqual(response.status_code, self.success_status)

    def test_regular_user_success_status(self):
        """
        Tests to ensure that a successful request submitted by a non-admin user returns the expected
        status code.
        :return: None
        """
        response = self.send(user="user_1")
        self.assertEqual(response.status_code, self.success_status)

    def test_admin_user_success_status(self):
        """
        Tests to ensure that a successful request submitted by an administrative user returns the
        expected status code.
        :return: None
        """
        response = self.send(user="admin_1")
        self.assertEqual(response.status_code, self.success_status)

    @property
    def success_status(self):
        """
        Get the HTTP status code that indicates a successful response has been submitted.
        :return: the HTTP status code that indicates a successful response has been submitted.
        """
        return self._success_status


class ExporterTestCaseMixin(object):
    """
    This is a mixin class that provides some default unit tests to ensure that the data returned
    by an APIView that has exporting functionality contains the expected results.
    """

    def get_export_query_string_for_type(self, export_type):
        """
        Get a string containing the query string to include in requests for exporting data to the given
        type.
        :param export_type: A string representing the type to export to.
        :return: A query string to include in requests for exporting data to the given type.
        """
        return "%s=%s" % (settings.EXPORT_PARAM, export_type)

    def test_export_xlsx_status(self):
        """
        Tests to ensure that exporting to an Excel sheet returns the expected status code.
        :return: None
        """
        query_string = self.get_export_query_string_for_type("xlsx")
        response = self.send(user=self.auth_user, query_string=query_string)
        self.assertEqual(response.status_code, 200)

    def test_export_xlsx_contains_disposition(self):
        """
        Tests to ensure that exporting to an Excel sheet returns a response that has a content-disposition
        header.
        :return: None
        """
        query_string = self.get_export_query_string_for_type("xlsx")
        response = self.send(user=self.auth_user, query_string=query_string)
        self.assertTrue(response.has_header("Content-Disposition"))

    def test_export_xlsx_content_type(self):
        """
        Tests to ensure that exporting to an Excel sheet returns a response that has the expected content
        type.
        :return: None
        """
        query_string = self.get_export_query_string_for_type("xlsx")
        response = self.send(user=self.auth_user, query_string=query_string)
        content_type = response._headers["content-type"][1]
        self.assertEqual(ExcelExporter.get_content_type(), content_type)

    def test_export_csv_status(self):
        """
        Tests to ensure that exporting to a CSV file returns the expected status code.
        :return: None
        """
        query_string = self.get_export_query_string_for_type("csv")
        response = self.send(user=self.auth_user, query_string=query_string)
        self.assertEqual(response.status_code, 200)

    def test_export_csv_contains_disposition(self):
        """
        tests to ensure that exporting to a CSV file returns a response that has a content-disposition header.
        :return: None
        """
        query_string = self.get_export_query_string_for_type("csv")
        response = self.send(user=self.auth_user, query_string=query_string)
        self.assertTrue(response.has_header("Content-Disposition"))

    def test_export_csv_content_type(self):
        """
        Tests to ensure that exporting to a CSV file returns a response that has the expected content type.
        :return: None
        """
        query_string = self.get_export_query_string_for_type("csv")
        response = self.send(user=self.auth_user, query_string=query_string)
        content_type = response._headers["content-type"][1]
        self.assertEqual(CsvExporter.get_content_type(), content_type)

    @property
    def auth_user(self):
        """
        Get a string depicting the user to send requests as by default.
        :return: a string depicting the user to send requests as by default.
        """
        return "user_1"


class RelatedTestCaseMixin(object):
    """
    This is a mixin class that provides some default unit tests to ensure that data returned by an
    Elasticsearch related APIView contains the expected results.
    """

    def test_response_contains_results(self):
        """
        Tests to ensure that the response contains at least one object.
        :return: None
        """
        response = self.send(user=self.auth_user)
        content = response.json()
        self.assertGreater(len(content["results"]), 0)

    def test_response_results_contain_types(self):
        """
        Tests to ensure that all of the data objects returned in a response contain the type field.
        :return: None
        """
        response = self.send(user=self.auth_user)
        content = response.json()
        self.assertTrue(all(["type" in x for x in content["results"]]))

    @property
    def auth_user(self):
        """
        Get a string depicting the user to send requests as by default.
        :return: a string depicting the user to send requests as by default.
        """
        return "user_1"


class PaginatedTestCaseMixin(object):
    """
    This is a mixin class that provides some default unit tests to ensure that the data returned
    by an APIView that has paginated data contains the expected results.
    """

    def test_response_contains_count(self):
        """
        Tests to ensure that the response returned by the remote endpoint contains the count
        key.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertIn("count", response.json())

    def test_response_count_int(self):
        """
        Tests to ensure that the count value returned in the response contains an integer.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertTrue(isinstance(response.json()["count"], int))

    def test_response_count_matches_results(self):
        """
        Tests to ensure that the value in the count field matches the number of results returned in
        the response.
        :return: None
        """
        response = self.send(user=self.auth_user)
        content = response.json()
        if content["count"] <= api_settings.PAGE_SIZE:
            self.assertEqual(content["count"], len(content["results"]))

    def test_response_contains_results(self):
        """
        Tests to ensure that the response returned by the remote endpoint contains the
        results key.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertIn("results", response.json())

    def test_response_results_list(self):
        """
        Tests to ensure that the results value in the response contains a list.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertTrue(isinstance(response.json()["results"], list))

    def test_response_contains_current_page(self):
        """
        Tests to ensure that the response returned by the remote endpoint contains the
        current_page key.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertIn("current_page", response.json())

    def test_response_current_page_int(self):
        """
        Tests to ensure that the current_page value returned by the remote endpoint contains an
        integer.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertTrue(isinstance(response.json()["current_page"], int))

    def test_response_contains_page_size(self):
        """
        Tests to ensure that the response returned by the remote endpoint contains the page_size
        key.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertIn("page_size", response.json())

    def test_response_page_size_int(self):
        """
        Tests to ensure that the page_size value returned by the remote endpoint contains an
        integer.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertTrue(isinstance(response.json()["page_size"], int))

    def test_response_contains_first_page(self):
        """
        Tests to ensure that the response returned by the remote endpoint contains the first_page
        key.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertIn("first_page", response.json())

    def test_response_first_page_int(self):
        """
        Tests to ensure that the first_page value returned by the remote endpoint contains an integer.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertTrue(isinstance(response.json()["first_page"], int))

    def test_response_contains_last_page(self):
        """
        Tests to ensure that the response returned by the remote endpoint contains the last_page key.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertIn("last_page", response.json())

    def test_response_last_page_int(self):
        """
        Tests to ensure that the last_page value returned by the remote endpoint contains an integer.
        :return: None
        """
        response = self.send(user=self.auth_user)
        self.assertTrue(isinstance(response.json()["last_page"], int))

    @property
    def auth_user(self):
        """
        Get a string depicting the user to send requests as by default.
        :return: a string depicting the user to send requests as by default.
        """
        return "user_1"


class ListTestCaseMixin(PaginatedTestCaseMixin):
    """
    This is a test case mixin for providing common test case functionality for views that support list
    functionality.
    """

    def send(self, *args, **kwargs):
        return self.send_list_request(*args, **kwargs)

    def send_list_request(self, *args, **kwargs):
        """
        Send a request to the configured endpoint to invoke the list functionality.
        :param args: Positional arguments to pass to the send request method.
        :param kwargs: Keyword arguments to pass to the send request method.
        :return: The response.
        """
        return self.list_method(*args, **kwargs)

    @property
    def list_method(self):
        """
        Get the method that should be invoked to send a list request.
        :return: the method that should be invoked to send a list request.
        """
        raise NotImplementedError("Subclasses must implement this!")


class CreateTestCaseMixin(object):
    """
    This is a test case mixin for providing common test case functionality for views that support create
    functionality.
    """

    def test_create_success_status(self):
        """
        Tests to ensure that a successful creation request returns the expected HTTP status code.
        :return: None
        """
        response = self.send_create_request(user=self.auth_user)
        self.assertEqual(response.status_code, self.create_success_status)

    def test_create_auth_user_success_status(self):
        """
        Tests to ensure that a successful creation request by self.auth_user user returns the expected HTTP status
        code.
        :return: None
        """
        response = self.send_create_request(user=self.auth_user)
        self.assertEqual(response.status_code, self.create_success_status)

    def test_create_admin_success_status(self):
        """
        Tests to ensure that a successful creation request by an admin user returns the expected HTTP status
        code.
        :return: None
        """
        response = self.send_create_request(user="admin_1")
        self.assertEqual(response.status_code, self.create_success_status)

    def test_create_creates_object(self):
        """
        Tests to ensure that a successful creation request correctly creates the expected object.
        :return: None
        """
        first_count = self.created_object_class.objects.count()
        self.send_create_request(user=self.auth_user)
        second_count = self.created_object_class.objects.count()
        self.assertEqual(first_count + 1, second_count)

    def send_create_request(self, *args, **kwargs):
        """
        Send a request to the configured endpoint to invoke the create functionality.
        :param args: Positional arguments to pass to the send request method.
        :param kwargs: Keyword arguments to pass to the send request method.
        :return: The response.
        """
        return self.create_method(*args, **kwargs)

    def get_last_created_of_class(self):
        """
        Get the most recently-created instance of the queried class.
        :return: The most recently created instance of the queried class.
        """
        return self.get_last_created(self.created_object_class)

    def assert_creation_succeeds(self, response):
        """
        Assert that the contents of the response indicate that a creation request was successful.
        :param response: The response to check.
        :return: None
        """
        self.assertEqual(response.status_code, self.create_success_status)

    @property
    def auth_user(self):
        """
        Get a string depicting the user to send requests as by default.
        :return: a string depicting the user to send requests as by default.
        """
        return "user_1"

    @property
    def create_method(self):
        """
        Get the method that should be invoked to send a create request.
        :return: the method that should be invoked to send a create request.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def created_object_class(self):
        """
        Get the class of the database object that is being created.
        :return: the class of the database object that is being created.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def create_success_status(self):
        """
        Get the HTTP status code that should be returned by successful creation requests.
        :return: the HTTP status code that should be returned by successful creation requests.
        """
        return 201


class CreateForUserTestCaseMixin(CreateTestCaseMixin):
    """
    This is a test case mixin class that verifies that created objects are owned by the expected
    user.
    """

    def test_create_correct_user(self):
        """
        Tests to ensure that the newly-created object is owned by the expected user.
        :return: None
        """
        self.send_create_request(user=self.auth_user)
        created = self.get_last_created_of_class()
        user = self.get_user(user=self.auth_user)
        self.assertEqual(created.user, user)


class RetrieveTestCaseMixin(object):
    """
    This is a test case mixin class that performs standard testing for endpoints that support object
    retrieval.
    """

    def test_retrieve_success(self):
        """
        Tests that submitting a retrieve request succeeds.
        :return: None
        """
        self.assert_retrieve_succeeds(self.send_retrieve_request())

    def test_retrieve_regular_user_success(self):
        """
        Tests that submitting a retrieve request as a regular user succeeds.
        :return: None
        """
        self.assert_retrieve_succeeds(self.send_retrieve_request(user="user_1"))

    def test_retrieve_admin_user_success(self):
        """
        Tests that submitting a retrieve request as an administrative user succeeds.
        :return: None
        """
        self.assert_retrieve_succeeds(self.send_retrieve_request(user="admin_1"))

    def test_retrieve_not_owned_regular_fails(self):
        """
        Tests that submitting a retrieve request as a regular user to an instance of the class that
        the user does not own fails.
        :return: None
        """
        not_owned = self.get_retrieved_object_uuid("user_2")
        self.assert_retrieve_fails(self.send_retrieve_request(user="user_1", input_uuid=not_owned))

    def test_retrieve_unknown_fails(self):
        """
        Tests that submitting a retrieve request for a UUID that does not exist fails.
        :return: None
        """
        self.assert_retrieve_fails(self.send_retrieve_request(input_uuid=str(uuid4())))

    def test_retrieve_not_owned_admin_succeeds(self):
        """
        Tests that submitting a retrieve request as an administrative user to an instance of the class that
        the user does not own succeeds.
        :return: None
        """
        not_owned = self.get_retrieved_object_uuid("user_2")
        self.assert_retrieve_succeeds(self.send_retrieve_request(user="admin_1", input_uuid=not_owned))

    def assert_retrieve_fails(self, response, status_code=404):
        """
        Assert that the given response indicates a failed retrieval.
        :param response: The response to process.
        :param status_code: The expected failing status code.
        :return: None
        """
        self.assertEqual(response.status_code, status_code)

    def assert_retrieve_succeeds(self, response):
        """
        Assert that the given response indicates a successful retrieval.
        :param response: The response to process.
        :return: None
        """
        self.assertEqual(response.status_code, 200)

    def get_retrieved_object_uuid(self, user):
        """
        Get the UUID of the instance of this class that the requesting user should use.
        :param user: A string depicting the user to retrieve the UUID for.
        :return: The UUID of the instance of this class that the requesting user should use.
        """
        return str(self.get_object_by_class_for_user(user=user, object_class=self.retrieved_object_class).uuid)

    def send_retrieve_request(self, *args, **kwargs):
        """
        Send a request to the configured endpoint to invoke the retrieve functionality.
        :param args: Position arguments to pass to the send request method.
        :param kwargs: Keyword arguments to pass to the send request method.
        :return: The response.
        """
        input_uuid = kwargs.pop("input_uuid", None)
        user = kwargs.pop("user", "user_1")
        if input_uuid is None:
            input_uuid = self.get_retrieved_object_uuid(user)
        kwargs["user"] = user
        kwargs["input_uuid"] = input_uuid
        return self.retrieve_method(*args, **kwargs)

    @property
    def retrieve_method(self):
        """
        Get the method that should be invoked to send a retrieve call to the server.
        :return: The method that should be invoked to send a retrieve call to the server.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def retrieved_object_class(self):
        """
        Get the class of the object that is being retrieved.
        :return: The class of the object that is being retrieved.
        """
        raise NotImplementedError("Subclasses must implement this!")


class DeleteTestCaseMixin(object):
    """
    This is a test case mixin class that performs default unit testing functionality for views that
    support delete functionality.
    """

    def test_delete_deletes_object(self):
        """
        Tests to ensure that a delete request successfully deletes the object from the database.
        :return: None
        """
        model_instance = self.create_delete_object_for_user(user=self.auth_user)
        first_count = self.deleted_object_class.objects.count()
        self.send_delete_request(user=self.auth_user, input_uuid=model_instance.uuid)
        second_count = self.deleted_object_class.objects.count()
        self.assertEqual(first_count, second_count + 1)

    def test_delete_deletes_object_regular(self):
        """
        Tests to ensure that a delete request submitted by a regular user successfully deletes the
        object from the database.
        :return: None
        """
        model_instance = self.create_delete_object_for_user(user="user_1")
        first_count = self.deleted_object_class.objects.count()
        self.send_delete_request(input_uuid=model_instance.uuid, user="user_1")
        second_count = self.deleted_object_class.objects.count()
        self.assertEqual(first_count, second_count + 1)

    def test_delete_deletes_object_admin(self):
        """
        Tests to ensure that a delete request submitted by an admin user successfully deletes the
        object from the database.
        :return: None
        """
        model_instance = self.create_delete_object_for_user(user="admin_1")
        first_count = self.deleted_object_class.objects.count()
        self.send_delete_request(input_uuid=model_instance.uuid, user="admin_1")
        second_count = self.deleted_object_class.objects.count()
        self.assertEqual(first_count, second_count + 1)

    def test_delete_success_status(self):
        """
        Tests to ensure that a successful delete request returns the expected HTTP status code.
        :return: None
        """
        model_instance = self.create_delete_object_for_user()
        self.assert_delete_success(self.send_delete_request(input_uuid=model_instance.uuid))

    def test_delete_success_empty_body(self):
        """
        Tests to ensure that a successful delete request returns a response with an empty body.
        :return: None
        """
        model_instance = self.create_delete_object_for_user()
        response = self.send_delete_request(input_uuid=model_instance.uuid)
        self.assertEqual(response.content, "")

    def test_delete_regular_not_owned_fails(self):
        """
        Tests to ensure that a delete request submitting by a regular user to delete an object
        not owned by them fails.
        :return: None
        """
        model_instance = self.create_delete_object_for_user(user="user_2")
        response = self.send_delete_request(input_uuid=model_instance.uuid, user="user_1")
        self.assert_delete_fails(response, status_code=404)

    def test_delete_admin_not_owned_succeeds(self):
        """
        Tests to ensure that a delete request submitted by an admin user to delete an object not
        owned by them succeeds.
        :return: None
        """
        model_instance = self.create_delete_object_for_user(user="user_1")
        response = self.send_delete_request(input_uuid=model_instance.uuid, user="admin_1")
        self.assert_delete_success(response)

    def test_delete_unknown_fails(self):
        """
        Tests to ensure that a delete request containing a UUID that is not found in the database
        fails.
        :return: None
        """
        self.assert_delete_fails(self.send_delete_request(input_uuid=str(uuid4())), status_code=404)

    def assert_delete_fails(self, response, status_code=400):
        """
        Assert that the given response indicates that a delete request was not successful.
        :param response: The response to check.
        :param status_code: The failure status code to check for.
        :return: None
        """
        self.assertEqual(response.status_code, status_code)

    def assert_delete_success(self, response):
        """
        Assert that the given response indicates that a delete request was successful.
        :param response: The response to check.
        :return: None
        """
        self.assertEqual(response.status_code, self.delete_success_status)

    def create_delete_object_for_user(self, user="user_1"):
        """
        Create and return an instance of the model class that the tested view is meant to delete
        and ensure that the object is associated with the given user.
        :param user: A string depicting the user to associate the object with.
        :return: The newly-created object.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def send_delete_request(self, *args, **kwargs):
        """
        Send a delete request to the configured endpoint and return the HTTP response.
        :param args: Positional arguments for the send delete request method.
        :param kwargs: Keyword arguments for the send delete request method.
        :return: The HTTP response.
        """
        return self.delete_method(*args, **kwargs)

    @property
    def deleted_object_class(self):
        """
        Get the model class for the object that is being deleted.
        :return: the model class for the object that is being deleted.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def delete_method(self):
        """
        Get the method that should be invoked to send a delete call to the server.
        :return: the method that should be invoked to send a delete call to the server.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def delete_success_status(self):
        """
        Get the status code that should be expected when a successful delete is performed.
        :return: the status code that should be expected when a successful delete is performed.
        """
        return 204


class UpdateTestCaseMixin(object):
    """
    This is a test case mixin that contains default test case functionality for testing APIView
    handlers that support update functionality.
    """

    def test_update_success(self):
        """
        Tests that a successful update request returns the expected status code.
        :return: None
        """
        self.assert_update_success(self.send_update_request(user=self.auth_user))

    def test_update_regular_success(self):
        """
        Tests that a successful update request from a regular user returns the expected status code.
        :return: None
        """
        self.assert_update_success(self.send_update_request(user="user_1"))

    def test_update_admin_success(self):
        """
        Tests that a successful update request from an admin user returns the expected status code.
        :return: None
        """
        self.assert_update_success(self.send_update_request(user="admin_1"))

    def test_update_unknown_uuid_fails(self):
        """
        Tests that an update request to update an object based on a random UUID fails.
        :return: None
        """
        self.assert_update_fails(self.send_update_request(user=self.auth_user, input_uuid=str(uuid4())), status_code=404)

    def test_update_regular_not_owned_fails(self):
        """
        Tests that an update request to update an object not owned by the requesting (regular) user
        fails.
        :return: None
        """
        model_instance = self.get_update_object_for_user(user="user_2")
        response = self.send_update_request(input_uuid=str(model_instance.uuid), user="user_1")
        self.assert_update_fails(response, status_code=404)

    def test_update_admin_not_owned_succeeds(self):
        """
        Tests that an update request to update an object not owned by the requesting (admin) user
        succeeds.
        :return: None
        """
        model_instance = self.get_update_object_for_user(user="user_1")
        response = self.send_update_request(input_uuid=str(model_instance.uuid), user="admin_1")
        self.assert_update_success(response)

    def assert_update_fails(self, response, status_code=400):
        """
        Assert that the given response indicates a failed update request.
        :param response: The response to check.
        :param status_code: The status code indicating failure.
        :return: None
        """
        self.assertEqual(response.status_code, status_code)

    def assert_update_success(self, response):
        """
        Assert that the given response indicates a successful update.
        :param response: The response to check.
        :return: None
        """
        self.assertEqual(response.status_code, self.update_success_status)

    def get_update_object_for_user(self, user="user_1"):
        """
        Get an instance of the referenced model class owned by the given user.
        :param user: The user to retrieve the instance for.
        :return: An instance of the referenced model class owned by the given user.
        """
        return self.get_object_by_class_for_user(user=user, object_class=self.updated_model_class)

    def send_update_request(self, *args, **kwargs):
        """
        Send the update request to the API endpoint and return the response.
        :param args: Positional arguments for the update request.
        :param kwargs: Keyword arguments for the update request.
        :return: The HTTP response.
        """
        return self.update_method(*args, **kwargs)

    @property
    def auth_user(self):
        """
        Get a string depicting the user to send requests as by default.
        :return: a string depicting the user to send requests as by default.
        """
        return "user_1"

    @property
    def updated_model_class(self):
        """
        Get the class for the model object that is being updated through the referenced APIView.
        :return: the class for the model object that is being updated through the referenced APIView.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def update_method(self):
        """
        Get the method that should be invoked to submit an update request to the API endpoint.
        :return: the method that should be invoked to submit an update request to the API endpoint.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def update_success_status(self):
        """
        Get the default status code that successful updates will respond with.
        :return: the default status code that successful updates will respond with.
        """
        return 200


class PresentableTestCaseMixin(object):
    """
    This is a test case mixin that provides default testing functionality for test cases that test
    APIView functionality for data presentation.
    """

    presentation_fields = ["fields", "sortable_fields", "filter_fields"]

    def test_presentation_returns_fields(self):
        """
        Tests that submitting a presentation request returns a response that contains the queried object's
        fields.
        :return: None
        """
        response = self.send_presentation_request(user=self.auth_user)
        self.assertTrue("fields" in response.json())
        
    def test_presentation_returns_fields_list(self):
        """
        Tests that submitting a presentation request returns a response with a list of fields.
        :return: None
        """
        response = self.send_presentation_request(user=self.auth_user)
        self.assertTrue(isinstance(response.json()["fields"], list))

    def test_presentation_returns_fields_length(self):
        """
        Tests that submitting a presentation request returns a response with a list of fields that is
        not empty.
        :return: None
        """
        response = self.send_presentation_request(user=self.auth_user)
        self.assertTrue(len(response.json()["fields"]) > 0)

    def test_presentation_returns_sortable_fields(self):
        """
        Tests that submitting a presentation request returns a response that contains the queried object's
        sortable fields.
        :return: None
        """
        response = self.send_presentation_request(user=self.auth_user)
        self.assertTrue("sortable_fields" in response.json())

    def test_presentation_returns_sortable_fields_list(self):
        """
        Tests that submitting a presentation request returns a response with a list of sortable fields.
        :return: None
        """
        response = self.send_presentation_request(user=self.auth_user)
        self.assertTrue(isinstance(response.json()["sortable_fields"], list))

    def test_presentation_returns_filter_fields(self):
        """
        Tests that submitting a presentation request returns a response that contains the queried object's
        filter fields.
        :return: None
        """
        response = self.send_presentation_request(user=self.auth_user)
        self.assertTrue("filter_fields" in response.json())

    def test_presentation_returns_filter_fields_list(self):
        """
        Tests that submitting a presentation request returns a response with a list of filterable fields.
        :return: None
        """
        response = self.send_presentation_request(user=self.auth_user)
        self.assertTrue(isinstance(response.json()["filter_fields"], list))

    def test_presentation_response_keys(self):
        """
        Tests that submitting a presentation request returns a response with only the expected keys.
        :return: None
        """
        response = self.send_presentation_request(user=self.auth_user)
        content = response.json()
        for expected_field in self.presentation_fields:
            content.pop(expected_field)
        self.assertEqual(len(content), 0)

    def send_presentation_request(self, *args, **kwargs):
        """
        Send a request to the API endpoint to retrieve presentation data.
        :param args: Positional arguments to pass to the send method.
        :param kwargs: Keyword arguments to pass to the send method.
        :return: An HTTP response.
        """
        query_string = kwargs.pop("query_string", None)
        if query_string is not None:
            from lib.parsing import QueryStringWrapper
            wrapper = QueryStringWrapper(query_string)
            wrapper.add_argument(key=settings.PRESENTATION_PARAM)
            query_string = str(wrapper)
        else:
            query_string = settings.PRESENTATION_PARAM
        kwargs["query_string"] = query_string
        return self.presentation_method(*args, **kwargs)

    @property
    def auth_user(self):
        """
        Get a string depicting the user to send requests as by default.
        :return: a string depicting the user to send requests as by default.
        """
        return "user_1"

    @property
    def presentation_method(self):
        """
        Get the method that should be invoked to send a request to the API to get presentation data.
        :return: the method that should be invoked to send a request to the API to get presentation data.
        """
        raise NotImplementedError("Subclasses must implement this!")


class CustomFieldsMixin(object):
    """
    This is a test case mixin that provides default test case functionality for testing endpoints that allow
    users to specify fields to include and exclude.
    """

    ignored_fields = ["type"]

    def _assert_custom_fields_request_failed(self, response, status_code=400):
        """
        Assert that the given response indicates an error was thrown when attempting to specify fields for
        inclusion and exclusion.
        :param response: The response to check.
        :param status_code: The status code expected to indicate failure.
        :return: None
        """
        self.assertEqual(response.status_code, status_code)

    def __get_object_from_response(self, response):
        """
        Parse the contents of the response and return a JSON object reflecting one of the data objects
        returned by the response.
        :param response: The response to process.
        :return: A JSON object representing the contents of the a single data object found in the response.
        """
        if self.response_has_many:
            return response.json()["results"][0]
        else:
            return response.json()

    def test_custom_fields_include_success(self):
        """
        Tests that submitting a request with a field included returns a response with the expected field.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, include_fields=[self.custom_fields_field])
        data_object = self.__get_object_from_response(response)
        self.assertTrue(self.custom_fields_field in data_object)

    def test_custom_fields_include_fields(self):
        """
        Tests that submitting a request with a field included returns a response containing only the fields
        specified for inclusion.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, include_fields=[self.custom_fields_field])
        data_object = self.__get_object_from_response(response)
        object_keys = data_object.keys()
        object_keys.remove(self.custom_fields_field)
        for ignored_field in self.ignored_fields:
            if ignored_field in object_keys:
                object_keys.remove(ignored_field)
        self.assertEqual(len(object_keys), 0)

    def test_custom_fields_include_fields_empty_fails(self):
        """
        Tests that submitting a request with no fields included raises an error.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, include_fields=[])
        self._assert_custom_fields_request_failed(response)

    def test_custom_fields_include_fields_unknown_fails(self):
        """
        Tests that submitting a request with a random include field raises an error.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, include_fields=["asd123asd123"])
        self._assert_custom_fields_request_failed(response)

    def test_custom_fields_exclude_success(self):
        """
        Tests that submitting a request with a field excluded returns a response with the expected field
        excluded.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, exclude_fields=[self.custom_fields_field])
        data_object = self.__get_object_from_response(response)
        self.assertFalse(self.custom_fields_field in data_object)

    def test_custom_fields_exclude_unknown_success(self):
        """
        Tests that submitting a request with a random unknown field excluded returns a successful response.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, exclude_fields=["asd123asd123"])
        self.assertEqual(response.status_code, 200)

    def test_custom_fields_include_priority(self):
        """
        Tests that submitting a request with both included and excluded fields gives priority to the
        included fields.
        :return: None
        """
        response = self.send_custom_fields_request(
            user=self.auth_user,
            include_fields=[self.custom_fields_field],
            exclude_fields=[self.custom_fields_field],
        )
        self.assertEqual(response.status_code, 200)

    def send_custom_fields_request(self, include_fields=None, exclude_fields=None, *args, **kwargs):
        """
        Send a request to the API endpoint to retrieve a response with filtered fields.
        :param include_fields: A list of fields to include in the response.
        :param exclude_fields: A list of fields to exclude from the response.
        :param args: Positional arguments to pass to the send method.
        :param kwargs: Keyword arguments to pass to the send method.
        :return: An HTTP response.
        """
        from lib.parsing import QueryStringWrapper
        query_string = kwargs.pop("query_string", None)
        if query_string is not None:
            wrapper = QueryStringWrapper(query_string)
        else:
            wrapper = QueryStringWrapper("")
        if include_fields is not None:
            wrapper.add_argument(key=settings.INCLUDE_FIELDS_PARAM, value=",".join(include_fields))
        if exclude_fields is not None:
            wrapper.add_argument(key=settings.EXCLUDE_FIELDS_PARAM, value=",".join(exclude_fields))
        kwargs["query_string"] = str(wrapper)
        return self.custom_fields_method(*args, **kwargs)

    @property
    def auth_user(self):
        """
        Get a string depicting the user to send requests as by default.
        :return: a string depicting the user to send requests as by default.
        """
        return "user_1"

    @property
    def custom_fields_method(self):
        """
        Get the method that should be invoked to send a request to the API to test field inclusion.
        :return: the method that should be invoked to send a request to the API to test field inclusion.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def custom_fields_field(self):
        """
        Get a field found on the queried data model to use in testing.
        :return: a field found on the queried data model to use in testing.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def response_has_many(self):
        """
        Get whether or not the response returned by the API contains multiple instances of queried data.
        :return: whether or not the response returned by the API contains multiple instances of queried data.
        """
        raise NotImplementedError("Subclasses must implement this!")


class AdminOnlyMixin(object):
    """
    This is a test case mixin class that tests to make sure that functionality is only available to administrative
    users.
    """

    def test_admin_user_request_succeeds(self):
        """
        Tests to ensure that a request submitted by an admin user is successful.
        :return: None
        """
        self.assert_request_succeeds(self.admin_test_method(user="admin_1"))

    def test_non_admin_user_request_fails(self):
        """
        Tests to ensure that a request submitted by a regular user is not successful.
        :return: None
        """
        self.assert_request_not_authorized(self.admin_test_method(user="user_1"))

    def test_no_authentication_request_fails(self):
        """
        Tests to ensure that a request submitted without authentication is not successful.
        :return: None
        """
        self.assert_request_requires_auth(self.admin_test_method(login=False))

    @property
    def admin_test_method(self):
        """
        Get the method that should be invoked to test if administrative users only can access the handler.
        :return: the method that should be invoked to test if administrative users only can access the handler.
        """
        raise NotImplementedError("Subclasses must implement this!")


class ExporterCustomFieldsMixin(CustomFieldsMixin):
    """
    This is a test case mixin class that extends the standard custom fields testing and augments the tests
    with testing to ensure that exportation includes only the specified fields.
    """

    def test_custom_fields_export_csv_includes_success(self):
        """
        Tests that exporting a CSV file and specifying fields to include returns a successful status code.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, export_type="csv", include_fields=[self.custom_fields_field])
        self.assertEqual(response.status_code, 200)

    def test_custom_fields_export_csv_empty_includes_fails(self):
        """
        Tests that exporting a CSV file and specifying no fields to include returns an error.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, export_type="csv", include_fields=[])
        self._assert_custom_fields_request_failed(response)

    def test_custom_fields_export_csv_includes_field(self):
        """
        Tests that exporting a CSV file and specifying fields to include returns a CSV file that contains
        the expected field.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, export_type="csv", include_fields=[self.custom_fields_field])
        first_line = response.content.split("\n")[0].strip()
        self.assertTrue(self.custom_fields_field in first_line)

    def test_custom_fields_export_csv_include_fields(self):
        """
        Tests that exporting a CSV file and specifying fields to include returns a CSV file that contains the
        expected field.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, export_type="csv", include_fields=[self.custom_fields_field])
        first_line = response.content.split("\n")[0].strip()
        fields = [x.strip() for x in first_line.split(",")]
        fields.remove(self.custom_fields_field)
        for ignored_field in self.ignored_fields:
            if ignored_field in fields:
                fields.remove(ignored_field)
        self.assertTrue(len(fields) == 0)

    def test_custom_fields_export_csv_exclude_success(self):
        """
        Tests that exporting a CSV file and specifying fields to exclude returns a successful status code.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, export_type="csv", exclude_fields=[self.custom_fields_field])
        self.assertEqual(response.status_code, 200)

    def test_custom_fields_export_csv_exclude_fields(self):
        """
        Tests that exporting a CSV file and specifying fields to exclude returns a CSV file that does not
        include those fields.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, export_type="csv", exclude_fields=[self.custom_fields_field])
        first_line = response.content.split("\n")[0].strip()
        self.assertFalse(self.custom_fields_field in first_line)

    def test_custom_fields_export_excel_includes_success(self):
        """
        Tests that exporting an Excel sheet and specifying fields to include returns a successful status code.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, export_type="xlsx", include_fields=[self.custom_fields_field])
        self.assertEqual(response.status_code, 200)

    def test_custom_fields_export_excel_includes_fails(self):
        """
        Tests that exporting an Excel sheet and specifying no fields to include returns an error.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, export_type="xlsx", include_fields=[])
        self._assert_custom_fields_request_failed(response)

    def test_custom_fields_export_excel_excludes_success(self):
        """
        Tests that exporting an Excel sheet and specifying fields to exclude returns a successful status code.
        :return: None
        """
        response = self.send_custom_fields_request(user=self.auth_user, export_type="xlsx", exclude_fields=[self.custom_fields_field])
        self.assertEqual(response.status_code, 200)

    def send_custom_fields_request(self, export_type=None, *args, **kwargs):
        """
        Send a request to the API endpoint to include or exclude fields and to export the queried data to
        the given format.
        :param export_type: A string depicting the format to export data to.
        :param args: Positional arguments to pass to the send method.
        :param kwargs: Keyword arguments to pass to the send method.
        :return: An HTTP response.
        """
        if export_type is not None:
            from lib.parsing import QueryStringWrapper
            query_string = kwargs.pop("query_string", None)
            if query_string is not None:
                wrapper = QueryStringWrapper(query_string)
            else:
                wrapper = QueryStringWrapper("")
            wrapper.add_argument(key=settings.EXPORT_PARAM, value=export_type)
            kwargs["query_string"] = str(wrapper)
        return super(ExporterCustomFieldsMixin, self).send_custom_fields_request(*args, **kwargs)
