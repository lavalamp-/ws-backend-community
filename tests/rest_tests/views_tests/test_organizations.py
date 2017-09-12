# -*- coding: utf-8 -*-
from __future__ import absolute_import

from uuid import uuid4
from django.db import IntegrityError
from mock import MagicMock
from django.db.models import Q

import rest.models
from lib import WsFaker
from ..base import WsDjangoViewTestCase
from ..mixin import ParameterizedRouteMixin, ListTestCaseMixin, CreateTestCaseMixin, ExporterTestCaseMixin, \
    CreateForUserTestCaseMixin, UpdateTestCaseMixin, RetrieveTestCaseMixin, DeleteTestCaseMixin, \
    PresentableTestCaseMixin, ExporterCustomFieldsMixin, CustomFieldsMixin
from tasknode.tasks import handle_placed_order, send_emails_for_placed_order, initialize_organization


# class TestNetworksByOrganizationView(
#     ListTestCaseMixin,
#     CreateTestCaseMixin,
#     ParameterizedRouteMixin,
#     ExporterCustomFieldsMixin,
#     ExporterTestCaseMixin,
#     PresentableTestCaseMixin,
#     WsDjangoViewTestCase,
# ):
#     """
#     This is a test case for the NetworksByOrganizationView APIView.
#     """
#
#     _api_route = "/organizations/%s/networks/"
#     _url_parameters = None
#
#     def __send_list_request(self, user="user_1", query_string=None, login=True):
#         """
#         Send an HTTP request to the configured API endpoint and return the response.
#         :param user: A string depicting the user to send the request as.
#         :param query_string: The query string to include in the URL.
#         :param login: Whether or not to log the requesting user in.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         organization = self.get_organization_for_user(user=user)
#         self._url_parameters = str(organization.uuid)
#         return self.get(query_string=query_string)
#
#     def __send_create_request(
#             self,
#             user="user_1",
#             query_string=None,
#             login=True,
#             org_uuid="POPULATE",
#             include_name=True,
#             name="Awesome Network",
#             include_mask_length=True,
#             mask_length=24,
#             include_address=True,
#             address="8.8.8.8",
#     ):
#         """
#         Send an HTTP request to the configured API endpoint to create a new network for the organization
#         and return the response.
#         :param user: A string depicting the user to submit the request as.
#         :param query_string: The query string to include in the URL.
#         :param login: Whether or not to log the requesting user in before sending the request.
#         :param org_uuid: The UUID of the organization to include in the request.
#         :param include_name: Whether or not to include the network name in the request.
#         :param name: The network name to include in the request.
#         :param include_mask_length: Whether or not to include the mask length in the request.
#         :param mask_length: The mask length to include in the request.
#         :param include_address: Whether or not to include the address in the request.
#         :param address: The address to include in the request.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         to_send = {}
#         if org_uuid == "POPULATE":
#             organization = self.get_organization_for_user(user=user)
#             org_uuid = str(organization.uuid)
#         if include_name:
#             to_send["name"] = name
#         if include_mask_length:
#             to_send["mask_length"] = mask_length
#         if include_address:
#             to_send["address"] = address
#         self._url_parameters = str(org_uuid)
#         return self.post(query_string=query_string, data=to_send)
#
#     def test_create_unknown_org_uuid_fails(self):
#         """
#         Tests that submitting a create request with an org UUID that is unknown fails.
#         :return: None
#         """
#         org_uuid = str(uuid4())
#         self.assert_request_not_found(self.send_create_request(org_uuid=org_uuid))
#
#     def test_create_not_owned_org_uuid_fails(self):
#         """
#         Tests that submitting a create request with an org UUID that is not owned by the requesting
#         user fails.
#         :return: None
#         """
#         other_org = self.get_organization_for_user(user="user_2")
#         self.assert_request_fails(self.send_create_request(user="user_1", org_uuid=other_org.uuid))
#
#     def test_create_assigns_correct_org_uuid(self):
#         """
#         Tests that submitting a successful create request populate the expected organization UUID for the
#         newly-created network.
#         :return: None
#         """
#         self.send_create_request()
#         network = self.get_last_created_network()
#         organization = self.get_organization_for_user()
#         self.assertEqual(network.organization_id, organization.uuid)
#
#     def test_create_not_owned_org_uuid_admin_success(self):
#         """
#         Tests that submitting a create request with an org UUID that is not owned by the requesting user
#         succeeds if the user is an admin.
#         :return: None
#         """
#         other_org = self.get_organization_for_user(user="user_1")
#         response = self.send_create_request(user="admin_1", org_uuid=other_org.uuid)
#         self.assertEqual(response.status_code, self.create_success_status)
#
#     def test_create_no_name_fails(self):
#         """
#         Tests that submitting a create request without a name fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(include_name=False))
#
#     def test_create_assigns_correct_name(self):
#         """
#         Tests that submitting a create request populates the name value of the network correctly.
#         :return: None
#         """
#         self.send_create_request(name="FOO BAR BAZ")
#         network = self.get_last_created_network()
#         self.assertEqual(network.name, "FOO BAR BAZ")
#
#     def test_create_no_mask_length_fails(self):
#         """
#         Tests that submitting a request with no mask length fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(include_mask_length=False))
#
#     def test_create_empty_mask_length_fails(self):
#         """
#         Tests that submitting a request with an empty mask length fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(mask_length=None))
#
#     def test_create_wrong_mask_length_fails(self):
#         """
#         Tests that submitting a request with an unexpected data type for mask length fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(mask_length="ASD123"))
#
#     def test_create_too_large_mask_length_fails(self):
#         """
#         Tests that submitting a request with a mask length that is too large fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(mask_length=33))
#
#     def test_create_too_small_mask_length_fails(self):
#         """
#         Tests that submitting a request with a mask length that is too small fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(mask_length=5))
#
#     def test_create_assigns_correct_mask_length(self):
#         """
#         Tests that a successful creation request assigns the expected value to the networks' mask length.
#         :return: None
#         """
#         self.send_create_request(mask_length=24)
#         network = self.get_last_created_network()
#         self.assertEqual(network.mask_length, 24)
#
#     def test_create_no_address_fails(self):
#         """
#         Tests that submitting a create request with no address fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(include_address=False))
#
#     def test_create_empty_address_fails(self):
#         """
#         Tests that submitting a create request with an empty address fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(address=None))
#
#     def test_create_invalid_address_fails(self):
#         """
#         Tests that submitting a create request with an invalid IP address fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(address="ASD123"))
#
#     def test_create_assigns_correct_address(self):
#         """
#         Tests that submitting a successful create request populates the expected value in the network's address.
#         :return: None
#         """
#         self.send_create_request(address="8.8.8.8", mask_length=24)
#         network = self.get_last_created_network()
#         self.assertEqual(network.address, "8.8.8.0")
#
#     def test_create_duplicate_address_mask_length_fails(self):
#         """
#         Tests that submitting a create request for a network that has an address and mask length pair that
#         already exists for the parent organization fails.
#         :return: None
#         """
#         self.send_create_request(address="8.8.8.8", mask_length=24)
#         with self.assertRaises(IntegrityError):
#             self.send_create_request(address="8.8.8.8", mask_length=24)
#
#     def test_create_duplicate_name_fails(self):
#         """
#         Tests that submitting a create request for a network that has the same name as an existing network fails.
#         :return: None
#         """
#         self.send_create_request(name="Totally Awesome")
#         with self.assertRaises(IntegrityError):
#             self.send_create_request(name="Totally Awesome")
#
#     @property
#     def custom_fields_field(self):
#         return "uuid"
#
#     @property
#     def custom_fields_method(self):
#         return self.__send_list_request
#
#     @property
#     def create_method(self):
#         return self.__send_create_request
#
#     @property
#     def created_object_class(self):
#         from rest.models import Network
#         return Network
#
#     @property
#     def list_method(self):
#         return self.__send_list_request
#
#     @property
#     def presentation_method(self):
#         return self.__send_list_request
#
#     @property
#     def response_has_many(self):
#         return True
#
#
# class TestDomainNamesByOrganizationView(
#     ListTestCaseMixin,
#     CreateTestCaseMixin,
#     PresentableTestCaseMixin,
#     ExporterCustomFieldsMixin,
#     ParameterizedRouteMixin,
#     ExporterTestCaseMixin,
#     WsDjangoViewTestCase,
# ):
#     """
#     This is a test case for testing the DomainNamesByOrganizationView APIView.
#     """
#
#     _api_route = "/organizations/%s/domain-names/"
#     _url_parameters = None
#
#     def __send_list_request(self, user="user_1", query_string=None, login=True):
#         """
#         Send an HTTP request to the configured API endpoint and return the response.
#         :param user: A string depicting the user to send the request as.
#         :param query_string: The query string to include in the URL.
#         :param login: Whether or not to log the requesting user in.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         organization = self.get_organization_for_user(user=user)
#         self._url_parameters = str(organization.uuid)
#         return self.get(query_string=query_string)
#
#     def __send_create_request(
#             self,
#             user="user_1",
#             query_string=None,
#             login=True,
#             org_uuid="POPULATE",
#             include_name=True,
#             name="foo.bar.com",
#     ):
#         """
#         Send an HTTP request to the configured API endpoint to create a new domain name for the organization
#         and return the response.
#         :param user: A string depicting the user to submit the request as.
#         :param query_string: The query string to include in the URL.
#         :param login: Whether or not to log the requesting user in before sending the request.
#         :param org_uuid: The UUID of the organization to include in the request.
#         :param include_name: Whether or not to include the domain name in the request.
#         :param name: The domain name to include in the request.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         to_send = {}
#         if org_uuid == "POPULATE":
#             organization = self.get_organization_for_user(user=user)
#             org_uuid = str(organization.uuid)
#         if include_name:
#             to_send["name"] = name
#         self._url_parameters = str(org_uuid)
#         return self.post(query_string=query_string, data=to_send)
#
#     def test_create_unknown_org_uuid_fails(self):
#         """
#         Tests that submitting a create request with an org UUID that is unknown fails.
#         :return: None
#         """
#         org_uuid = str(uuid4())
#         self.assert_request_not_found(self.send_create_request(org_uuid=org_uuid))
#
#     def test_create_not_owned_org_uuid_fails(self):
#         """
#         Tests that submitting a create request with an org UUID that is not owned by the requesting
#         user fails.
#         :return: None
#         """
#         other_org = self.get_organization_for_user(user="user_2")
#         self.assert_request_fails(self.send_create_request(user="user_1", org_uuid=other_org.uuid))
#
#     def test_create_assigns_correct_org_uuid(self):
#         """
#         Tests that submitting a successful create request populate the expected organization UUID for the
#         newly-created network.
#         :return: None
#         """
#         self.send_create_request()
#         domain = self.get_last_created_domain_name()
#         organization = self.get_organization_for_user()
#         self.assertEqual(domain.organization_id, organization.uuid)
#
#     def test_create_not_owned_org_uuid_admin_success(self):
#         """
#         Tests that submitting a create request with an org UUID that is not owned by the requesting user
#         succeeds if the user is an admin.
#         :return: None
#         """
#         other_org = self.get_organization_for_user(user="user_1")
#         response = self.send_create_request(user="admin_1", org_uuid=other_org.uuid)
#         self.assertEqual(response.status_code, self.create_success_status)
#
#     def test_create_no_name_fails(self):
#         """
#         Tests that submitting a create request without a name fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(include_name=False))
#
#     def test_create_empty_name_fails(self):
#         """
#         Tests that submitting a create request with an empty name fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(name=None))
#
#     def test_create_invalid_name_fails(self):
#         """
#         Tests that submitting a create request with an invalid name fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(name="FOO BAR BAZ"))
#
#     def test_create_assigns_correct_name(self):
#         """
#         Tests that submitting a create request populates the name value of the network correctly.
#         :return: None
#         """
#         self.send_create_request(name="foo.bar.baz")
#         domain = self.get_last_created_domain_name()
#         self.assertEqual(domain.name, "foo.bar.baz")
#
#     def test_create_duplicate_name_fails(self):
#         """
#         Tests that submitting a create request for a network that has the same name as an existing network fails.
#         :return: None
#         """
#         self.send_create_request(name="foo.bar.baz")
#         with self.assertRaises(IntegrityError):
#             self.send_create_request(name="foo.bar.baz")
#
#     @property
#     def custom_fields_field(self):
#         return "uuid"
#
#     @property
#     def custom_fields_method(self):
#         return self.__send_list_request
#
#     @property
#     def create_method(self):
#         return self.__send_create_request
#
#     @property
#     def created_object_class(self):
#         from rest.models import DomainName
#         return DomainName
#
#     @property
#     def list_method(self):
#         return self.__send_list_request
#
#     @property
#     def presentation_method(self):
#         return self.__send_list_request
#
#     @property
#     def response_has_many(self):
#         return True
#
#
# class TestOrdersByOrganizationView(
#     ListTestCaseMixin,
#     CreateForUserTestCaseMixin,
#     PresentableTestCaseMixin,
#     ParameterizedRouteMixin,
#     ExporterCustomFieldsMixin,
#     ExporterTestCaseMixin,
#     WsDjangoViewTestCase,
# ):
#     """
#     This is a test case for the OrdersByOrganizationView APIView.
#     """
#
#     _api_route = "/organizations/%s/orders/"
#     _url_parameters = None
#
#     def __send_list_request(self, user="user_1", query_string=None, login=True):
#         """
#         Send an HTTP request to the configured API endpoint and return the response.
#         :param user: A string depicting the user to send the request as.
#         :param query_string: The query string to include in the URL.
#         :param login: Whether or not to log the requesting user in.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         organization = self.get_organization_for_user(user=user)
#         self._url_parameters = str(organization.uuid)
#         return self.get(query_string=query_string)
#
#     def __send_create_request(
#             self,
#             user="user_1",
#             query_string=None,
#             login=True,
#     ):
#         """
#         Send an HTTP request to the configured API endpoint to create a new order for the organization
#         and return the response.
#         :param user: A string depicting the user to submit the request as.
#         :param query_string: The query string to include in the URL.
#         :param login: Whether or not to log the requesting user in before sending the request.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         to_send = {}
#         organization = self.get_organization_for_user(user=user)
#         self._url_parameters = str(organization.uuid)
#         return self.post(query_string=query_string, data=to_send)
#
#     def test_create_no_scan_privs_fails(self):
#         """
#         Tests to ensure that a create request fails if the requesting user does not have permission to scan
#         the organization.
#         :return: None
#         """
#         org = self.get_organization_for_user(user="user_1")
#         user = self.get_user(user="user_1")
#         org.scan_group.users.remove(user)
#         response = self.send_create_request()
#         org.scan_group.users.add(user)
#         self.assertEquals(response.status_code, 403)
#
#     def test_create_assigns_correct_organization(self):
#         """
#         Tests to ensure that a create request assigns the correct organization to the order.
#         :return: None
#         """
#         organization = self.get_organization_for_user(user="user_1")
#         self.send_create_request(user="user_1")
#         order = self.get_last_created_order()
#         self.assertEqual(order.organization, organization)
#
#     def test_create_assigns_correct_user_email(self):
#         """
#         Tests to ensure that a create request assigns the correct user email to the order.
#         :return: None
#         """
#         user = self.get_user(user="user_1")
#         self.send_create_request(user="user_1")
#         order = self.get_last_created_order()
#         self.assertEqual(order.user_email, user.email)
#
#     def test_create_assigns_correct_scoped_domains_count(self):
#         """
#         Tests to ensure that a create request assigns the correct scoped_domains_count.
#         :return: None
#         """
#         organization = self.get_organization_for_user(user="user_1")
#         self.send_create_request(user="user_1")
#         order = self.get_last_created_order()
#         self.assertEqual(order.scoped_domains_count, organization.monitored_domains_count)
#
#     def test_create_assigns_correct_scoped_endpoints_count(self):
#         """
#         Tests to ensure that a create request assigns the correct scoped_endpoints_count.
#         :return: None
#         """
#         organization = self.get_organization_for_user(user="user_1")
#         self.send_create_request(user="user_1")
#         order = self.get_last_created_order()
#         self.assertEqual(order.scoped_endpoints_count, organization.monitored_networks_count)
#
#     def test_create_assigns_correct_scoped_endpoints_size(self):
#         """
#         Tests to ensure that a create request assigns the correct scoped_endpoints_size.
#         :return: None
#         """
#         organization = self.get_organization_for_user(user="user_1")
#         self.send_create_request(user="user_1")
#         order = self.get_last_created_order()
#         self.assertEqual(order.scoped_endpoints_size, organization.monitored_networks_size)
#
#     def test_create_does_not_assign_started_at(self):
#         """
#         Tests to ensure that a create request does not assign started_at.
#         :return: None
#         """
#         self.send_create_request(user="user_1")
#         order = self.get_last_created_order()
#         self.assertIsNone(order.started_at)
#
#     def test_create_does_not_assign_completed_at(self):
#         """
#         Tests to ensure that a create request does not assign completed_at.
#         :return: None
#         """
#         self.send_create_request(user="user_1")
#         order = self.get_last_created_order()
#         self.assertIsNone(order.completed_at)
#
#     def test_create_adds_correct_networks(self):
#         """
#         Tests to ensure that a create request adds the correct number of networks to the order.
#         :return: None
#         """
#         org = self.get_organization_for_user(user="user_1")
#         networks_count = org.monitored_networks_count
#         self.send_create_request(user="user_1")
#         order = self.get_last_created_order()
#         self.assertEqual(networks_count, order.networks.count())
#
#     def test_create_adds_correct_domains(self):
#         """
#         Tests to ensure that a create request adds the correct number of domain names to the order.
#         :return: None
#         """
#         org = self.get_organization_for_user(user="user_1")
#         domains_count = org.monitored_domains_count
#         self.send_create_request(user="user_1")
#         order = self.get_last_created_order()
#         self.assertEqual(domains_count, order.domain_names.count())
#
#     def test_create_no_monitored_endpoints_fails(self):
#         """
#         Tests to ensure that a create request fails when the related organization does not have
#         any domains names or networks as scoped for the scan.
#         :return: None
#         """
#         org = self.get_organization_for_user()
#         network_uuids = []
#         domain_uuids = []
#         for network in org.networks.all():
#             if network.scanning_enabled:
#                 network.scanning_enabled = False
#                 network_uuids.append(network.uuid)
#                 network.save()
#         for domain in org.domain_names.all():
#             if domain.scanning_enabled:
#                 domain.scanning_enabled = False
#                 domain_uuids.append(domain.uuid)
#                 domain.save()
#         response = self.send_create_request()
#         for network_uuid in network_uuids:
#             network = org.networks.get(pk=network_uuid)
#             network.scanning_enabled = True
#             network.save()
#         for domain_uuid in domain_uuids:
#             domain = org.domain_names.get(pk=domain_uuid)
#             domain.scanning_enabled = True
#             domain.save()
#         self.assert_request_fails(response)
#
#     @property
#     def custom_fields_field(self):
#         return "uuid"
#
#     @property
#     def custom_fields_method(self):
#         return self.__send_list_request
#
#     @property
#     def create_method(self):
#         return self.__send_create_request
#
#     @property
#     def created_object_class(self):
#         from rest.models import Order
#         return Order
#
#     @property
#     def list_method(self):
#         return self.__send_list_request
#
#     @property
#     def presentation_method(self):
#         return self.__send_list_request
#
#     @property
#     def response_has_many(self):
#         return True
#
#
# class TestOrganizationListView(
#     CreateTestCaseMixin,
#     ListTestCaseMixin,
#     PresentableTestCaseMixin,
#     ExporterCustomFieldsMixin,
#     ExporterTestCaseMixin,
#     WsDjangoViewTestCase,
# ):
#     """
#     This is a test case class for testing the OrganizationListView APIView.
#     """
#
#     _api_route = "/organizations/"
#     _original_initialize_method = None
#
#     def setUp(self):
#         """
#         Set up this test case by mocking out all calls to Celery task invocations.
#         :return: None
#         """
#         super(TestOrganizationListView, self).setUp()
#         self._original_initialize_method = initialize_organization.delay
#         initialize_organization.delay = MagicMock()
#
#     def tearDown(self):
#         """
#         Tear down this test case by replacing all mocked methods.
#         :return: None
#         """
#         initialize_organization.delay = self._original_initialize_method
#         super(TestOrganizationListView, self).tearDown()
#
#     def __send_create_request(
#             self,
#             user="user_1",
#             login=True,
#             query_string=None,
#             include_name=True,
#             name="Tester",
#             include_description=True,
#             description="Foo Bar Baz",
#     ):
#         """
#         Submit a request to the endpoint to create an organization and return the response.
#         :param user: The user to send the request on behalf of.
#         :param login: Whether or not to log in before sending the request.
#         :param query_string: The query string to include in the URL.
#         :param include_name: Whether or not to include the name in the submitted data.
#         :param name: The name to include.
#         :param include_description: Whether or not to include the description in the submitted data.
#         :param description: The description to include.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         to_send = {}
#         if include_name:
#             to_send["name"] = name
#         if include_description:
#             to_send["description"] = description
#         return self.post(query_string=query_string, data=to_send)
#
#     def __send_list_request(self, user="user_1", login=True, query_string=None):
#         """
#         Submit a request to the API endpoint to list all organizations for the given user.
#         :param user: The user to send the request on behalf of.
#         :param login: Whether or not to log in before submitting the request.
#         :param query_string: The query string to submit alongside the request.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         return self.get(query_string=query_string)
#
#     def test_create_no_name_fails(self):
#         """
#         Tests that a create request that does not contain a name fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(include_name=False))
#
#     def test_create_empty_name_fails(self):
#         """
#         Tests that a create request with an empty name fails.
#         :return: None
#         """
#         self.assert_request_fails(self.send_create_request(name=""))
#
#     def test_create_assigns_correct_name(self):
#         """
#         Tests that a create request associates the correct name with the newly-created organization.
#         :return: None
#         """
#         self.send_create_request(name="FOOBLY WOOBLY")
#         org = self.get_last_created_organization()
#         self.assertEqual(org.name, "FOOBLY WOOBLY")
#
#     def test_create_no_description_succeeds(self):
#         """
#         Tests that a create request that does not contain a description succeeds.
#         :return: None
#         """
#         self.assert_creation_succeeds(self.send_create_request(include_description=False))
#
#     def test_create_empty_description_succeeds(self):
#         """
#         Tests that a create request that contains an empty description succeeds.
#         :return: None
#         """
#         self.assert_creation_succeeds(self.send_create_request(description=None))
#
#     def test_create_assigns_correct_description(self):
#         """
#         Tests that a create request associates the correct description with the newly-created
#         organization.
#         :return: None
#         """
#         self.send_create_request(description="THIS IS A GREAT DESC")
#         org = self.get_last_created_organization()
#         self.assertEqual(org.description, "THIS IS A GREAT DESC")
#
#     def test_create_calls_initialize_org(self):
#         """
#         Tests that a successful create request calls initialize_organization.delay.
#         :return: None
#         """
#         self.send_create_request()
#         self.assertTrue(initialize_organization.delay.called)
#
#     def test_create_calls_initialize_org_arguments(self):
#         """
#         Tests that a successful create request calls initialize_organization.delay with the expected
#         arguments.
#         :return: None
#         """
#         self.send_create_request()
#         org = self.get_last_created_organization()
#         initialize_organization.delay.assert_called_with(org_uuid=unicode(org.uuid))
#
#     @property
#     def custom_fields_field(self):
#         return "uuid"
#
#     @property
#     def custom_fields_method(self):
#         return self.__send_list_request
#
#     @property
#     def create_method(self):
#         return self.__send_create_request
#
#     @property
#     def created_object_class(self):
#         return rest.models.Organization
#
#     @property
#     def list_method(self):
#         return self.__send_list_request
#
#     @property
#     def presentation_method(self):
#         return self.__send_list_request
#
#     @property
#     def response_has_many(self):
#         return True
#
#
# class TestOrganizationDetailView(
#     UpdateTestCaseMixin,
#     RetrieveTestCaseMixin,
#     PresentableTestCaseMixin,
#     CustomFieldsMixin,
#     DeleteTestCaseMixin,
#     ParameterizedRouteMixin,
#     WsDjangoViewTestCase,
# ):
#     """
#     This is a test case for testing the OrganizationDetailView APIView.
#     """
#
#     _api_route = "/organizations/%s/"
#     _url_parameters = None
#
#     def __send_delete_request(self, user="user_1", login=True, query_string=None, input_uuid=None):
#         """
#         Send a delete request to the API endpoint and return the response.
#         :param user: The user to submit the request as.
#         :param login: Whether or not to log the user in prior to sending the request.
#         :param query_string: The query string to submit alongside the URL.
#         :param input_uuid: The UUID of the organization to delete.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         self._url_parameters = str(input_uuid)
#         return self.delete(query_string=query_string)
#
#     def __send_retrieve_request(
#             self,
#             user="user_1",
#             login=True,
#             query_string=None,
#             input_uuid="POPULATE",
#     ):
#         """
#         Submit a request to the remote endpoint to retrieve the given organization.
#         :param user: The user to submit the request as.
#         :param login: Whether or not to log the user in prior to sending the request.
#         :param query_string: The query string to submit alongside the URL.
#         :param input_uuid: The UUID of the organization to retrieve.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         if input_uuid == "POPULATE":
#             org = self.get_organization_for_user(user=user)
#             input_uuid = str(org.uuid)
#         self._url_parameters = input_uuid
#         return self.get(query_string=query_string)
#
#     def __send_update_request(
#             self,
#             user="user_1",
#             login=True,
#             query_string=None,
#             input_uuid="POPULATE",
#             include_name=True,
#             name="HOOBLY",
#             include_description=True,
#             description="WOOPDYWOOPWOOP",
#     ):
#         """
#         Submit a request to the remote endpoint to update the given organization.
#         :param user: The user to submit the request as.
#         :param login: Whether or not to log the user in prior to sending the request.
#         :param query_string: The query string to submit alongside the URL.
#         :param input_uuid: The UUID of the organization to update.
#         :param include_name: Whether or not to include the name in the request.
#         :param name: The name to include in the request.
#         :param include_description: Whether or not to include the description in the request.
#         :param description: The description to include in the request.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         if input_uuid == "POPULATE":
#             org = self.get_organization_for_user(user=user)
#             input_uuid = str(org.uuid)
#         self._url_parameters = input_uuid
#         to_send = {}
#         if include_name:
#             to_send["name"] = name
#         if include_description:
#             to_send["description"] = description
#         return self.patch(query_string=query_string, data=to_send)
#
#     def test_update_empty_name_fails(self):
#         """
#         Tests that submitting an update request with an empty name fails.
#         :return: None
#         """
#         self.assert_update_fails(self.send_update_request(name=""))
#
#     def test_update_assigns_correct_name(self):
#         """
#         Tests that submitting an update request associates the correct name with the given organization.
#         :return: None
#         """
#         org = self.get_organization_for_user(user="user_1")
#         self.send_update_request(name="AWW CHICKA YEA", input_uuid=org.uuid, user="user_1")
#         org = self.get_organization_for_user(user="user_1")
#         self.assertEqual(org.name, "AWW CHICKA YEA")
#
#     def test_update_assigns_correct_description(self):
#         """
#         Tests that submitting an update request associates the correct description with the
#         given organization.
#         :return: None
#         """
#         org = self.get_organization_for_user(user="user_1")
#         self.send_update_request(description="AWW CHICKA YEA", input_uuid=org.uuid, user="user_1")
#         org = self.get_organization_for_user(user="user_1")
#         self.assertEqual(org.description, "AWW CHICKA YEA")
#
#     def create_delete_object_for_user(self, user="user_1"):
#         user = self.get_user(user=user)
#         org = rest.models.Organization.objects.create(**WsFaker.get_organization_kwargs())
#         org.add_admin_user(user)
#         return org
#
#     @property
#     def custom_fields_field(self):
#         return "uuid"
#
#     @property
#     def custom_fields_method(self):
#         return self.__send_retrieve_request
#
#     @property
#     def deleted_object_class(self):
#         return rest.models.Organization
#
#     @property
#     def delete_method(self):
#         return self.__send_delete_request
#
#     @property
#     def presentation_method(self):
#         return self.__send_retrieve_request
#
#     @property
#     def response_has_many(self):
#         return False
#
#     @property
#     def retrieved_object_class(self):
#         return rest.models.Organization
#
#     @property
#     def retrieve_method(self):
#         return self.__send_retrieve_request
#
#     @property
#     def updated_model_class(self):
#         return rest.models.Organization
#
#     @property
#     def update_method(self):
#         return self.__send_update_request
#
#
# class TestScanPortListView(
#     ListTestCaseMixin,
#     PresentableTestCaseMixin,
#     ExporterCustomFieldsMixin,
#     ExporterTestCaseMixin,
#     WsDjangoViewTestCase,
# ):
#     """
#     This is a test case for testing the ScanPortListView APIView.
#     """
#
#     _api_route = "/scan-ports/"
#
#     def __send_list_request(self, user="user_1", query_string=None, login=True):
#         """
#         Send an HTTP request to the configured API endpoint and return the response.
#         :param user: A string depicting the user to send the request as.
#         :param query_string: The query string to include in the URL.
#         :param login: Whether or not to log the requesting user in.
#         :return: The HTTP response.
#                 """
#         if login:
#             self.login(user=user)
#         return self.get(query_string=query_string)
#
#     def test_regular_user_list(self):
#         """
#         Tests that requesting the endpoint on behalf of a regular user returns the expected
#         number of results.
#         :return: None
#         """
#         response = self.__send_list_request(user="user_1")
#         user = self.get_user(user="user_1")
#         total_count = rest.models.ScanPort.objects.filter(
#             Q(scan_config__user=user) |
#             Q(scan_config__is_default=True) |
#             Q(
#                 scan_config__organization__auth_groups__users=user,
#                 scan_config__organization__auth_groups__name="org_read",
#             )
#         ).count()
#         self.assertEqual(response.json()["count"], total_count)
#
#     def test_admin_user_list(self):
#         """
#         Tests that requesting the endpoint on behalf of an admin user returns the expected
#         number of results.
#         :return: None
#         """
#         response = self.__send_list_request(user="admin_1")
#         total_count = rest.models.ScanPort.objects.count()
#         self.assertEqual(response.json()["count"], total_count)
#
#     @property
#     def custom_fields_field(self):
#         return "uuid"
#
#     @property
#     def custom_fields_method(self):
#         return self.__send_list_request
#
#     @property
#     def list_method(self):
#         return self.__send_list_request
#
#     @property
#     def presentation_method(self):
#         return self.__send_list_request
#
#     @property
#     def response_has_many(self):
#         return True
#
#
# class TestScanPortDetailView(
#     RetrieveTestCaseMixin,
#     DeleteTestCaseMixin,
#     PresentableTestCaseMixin,
#     CustomFieldsMixin,
#     ParameterizedRouteMixin,
#     WsDjangoViewTestCase,
# ):
#     """
#     This is a test case for the ScanPortDetailView APIView.
#     """
#
#     _api_route = "/scan-ports/%s/"
#     _url_parameters = None
#
#     def create_delete_object_for_user(self, user="user_1"):
#         scan_config = self.get_scan_config_for_user(user=user)
#         return scan_config.scan_ports.create(**WsFaker.get_scan_port_kwargs())
#
#     def __create_default_scan_config(self):
#         """
#         Create and return a ScanConfig that is configured as default.
#         :return: A ScanConfig configured as a default ScanConfig.
#         """
#         to_return = rest.models.ScanConfig.objects.create()
#         to_return.is_default = True
#         to_return.save()
#         return to_return
#
#     def __create_organization_for_user(self, user_string="user_1"):
#         user = self.get_user(user=user_string)
#         org = rest.models.Organization.objects.create(name="Name", description="Description")
#         org.add_admin_user(user)
#         org.save()
#         return org
#
#     def __send_delete_request(self, user="user_1", login=True, query_string=None, input_uuid="POPULATE"):
#         """
#         Send a delete request to the API endpoint and return the response.
#         :param user: The user to submit the request as.
#         :param login: Whether or not to log the user in prior to sending the request.
#         :param query_string: The query string to submit alongside the URL.
#         :param input_uuid: The UUID of the organization to delete.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         if input_uuid == "POPULATE":
#             order = self.get_scan_port_for_user(user=user)
#             input_uuid = str(order.uuid)
#         self._url_parameters = str(input_uuid)
#         return self.delete(query_string=query_string)
#
#     def __send_retrieve_request(self, user="user_1", query_string=None, login=True, input_uuid="POPULATE"):
#         """
#         Send an HTTP request to the configured API endpoint and return the response.
#         :param user: The user to send the request as.
#         :param query_string: The query string to include in the URL.
#         :param login: Whether or not to log in before sending the request.
#         :param input_uuid: The UUID of the order to retrieve.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         if input_uuid == "POPULATE":
#             order = self.get_scan_port_for_user(user=user)
#             input_uuid = str(order.uuid)
#         self._url_parameters = input_uuid
#         return self.get(query_string=query_string)
#
#     def test_delete_regular_is_default_fails(self):
#         """
#         Tests that attempting to delete a ScanPort from an is_default ScanConfig as a regular user fails.
#         :return: None
#         """
#         default_config = self.__create_default_scan_config()
#         response = self.__send_delete_request(user="user_1", input_uuid=default_config.scan_ports.first().uuid)
#         default_config.delete()
#         self.assert_request_not_authorized(response)
#
#     def test_delete_admin_is_default_succeeds(self):
#         """
#         Tests that attempting to delete a ScanPort from an is_default ScanConfig as an admin user succeeds.
#         :return: None
#         """
#         default_config = self.__create_default_scan_config()
#         response = self.__send_delete_request(user="admin_1", input_uuid=default_config.scan_ports.first().uuid)
#         default_config.delete()
#         self.assert_request_succeeds(response, status_code=204)
#
#     def test_retrieve_regular_is_default_succeeds(self):
#         """
#         Tests that attempting to retrieve a ScanPort from an is_default ScanConfig as a regular user succeeds.
#         :return: None
#         """
#         default_config = self.__create_default_scan_config()
#         response = self.__send_retrieve_request(user="user_1", input_uuid=default_config.scan_ports.first().uuid)
#         default_config.delete()
#         self.assert_request_succeeds(response)
#
#     def test_retrieve_admin_is_default_succeeds(self):
#         """
#         Tests that attempting to retrieve a ScanPort from an is_default ScanConfig as an admin user succeeds.
#         :return: None
#         """
#         default_config = self.__create_default_scan_config()
#         response = self.__send_retrieve_request(user="admin_1", input_uuid=default_config.scan_ports.first().uuid)
#         default_config.delete()
#         self.assert_request_succeeds(response)
#
#     def test_regular_user_delete_cant_be_modified_fails(self):
#         """
#         Tests that attempting to delete a ScanPort from a ScanConfig that the requesting user owns as a regular
#         user fails when the ScanConfig cannot be modified.
#         :return: None
#         """
#         scan_config = self.get_scan_config_for_user(user="user_1")
#         scan_config.order.has_been_placed = True
#         scan_config.order.save()
#         response = self.__send_delete_request(input_uuid=scan_config.scan_ports.first().uuid, user="user_1")
#         scan_config.order.has_been_placed = False
#         scan_config.order.save()
#         self.assert_request_not_authorized(response)
#
#     def test_admin_user_delete_cant_be_modified_fails(self):
#         """
#         Tests that attempting to delete a ScanPort from a ScanConfig that the requesting user owns as an admin
#         user fails when the ScanConfig cannot be modified.
#         :return: None
#         """
#         scan_config = self.get_scan_config_for_user(user="admin_1")
#         scan_config.order.has_been_placed = True
#         scan_config.order.save()
#         response = self.__send_delete_request(input_uuid=scan_config.scan_ports.first().uuid, user="admin_1")
#         scan_config.order.has_been_placed = False
#         scan_config.order.save()
#         self.assert_request_not_authorized(response)
#
#     def test_delete_as_org_admin_succeeds(self):
#         """
#         Tests that deleting an object from a ScanConfig related to an organization that the requesting
#         user has administrative permissions for succeeds.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         scan_config = org.scan_config
#         scan_port = scan_config.scan_ports.first()
#         response = self.__send_delete_request(input_uuid=scan_port.uuid, user="user_1")
#         org.delete()
#         self.assert_request_succeeds(response, status_code=204)
#
#     def test_delete_as_not_org_admin_fails(self):
#         """
#         Tests that deleting an object from a ScanConfig related to an organization that the requesting user
#         does not have administrative permissions for fails.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         user = self.get_user(user="user_1")
#         org.set_user_permissions(user=user, permission_level="write")
#         scan_config = org.scan_config
#         scan_port = scan_config.scan_ports.first()
#         response = self.__send_delete_request(input_uuid=scan_port.uuid, user="user_1")
#         org.delete()
#         self.assert_request_not_authorized(response)
#
#     def test_delete_as_not_org_admin_superuser_succeeds(self):
#         """
#         Tests that deleting an object from a ScanConfig related to an organization that the requesting user
#         does not have administrative permissions for succeeds when the requesting user is a superuser.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         scan_config = org.scan_config
#         scan_port = scan_config.scan_ports.first()
#         response = self.__send_delete_request(input_uuid=scan_port.uuid, user="admin_1")
#         org.delete()
#         self.assert_request_succeeds(response, status_code=204)
#
#     @property
#     def custom_fields_field(self):
#         return "uuid"
#
#     @property
#     def custom_fields_method(self):
#         return self.__send_retrieve_request
#
#     @property
#     def delete_method(self):
#         return self.__send_delete_request
#
#     @property
#     def deleted_object_class(self):
#         return rest.models.ScanPort
#
#     @property
#     def presentation_method(self):
#         return self.__send_retrieve_request
#
#     @property
#     def response_has_many(self):
#         return False
#
#     @property
#     def retrieve_method(self):
#         return self.__send_retrieve_request
#
#     @property
#     def retrieved_object_class(self):
#         return rest.models.ScanPort
#
#
# class TestRetrieveOrganizationScanConfig(
#     ParameterizedRouteMixin,
#     WsDjangoViewTestCase,
# ):
#     """
#     This is a test case for testing the retrieve_organization_scan_config function APIView.
#     """
#
#     _api_route = "/organizations/%s/scan-config/"
#     _url_parameters = None
#
#     def __create_organization_for_user(self, user_string="user_1"):
#         user = self.get_user(user=user_string)
#         org = rest.models.Organization.objects.create(name="Name", description="Description")
#         org.add_admin_user(user)
#         org.save()
#         return org
#
#     def __send_request(self, user="user_1", login=True, query_string=None, input_uuid=None):
#         """
#         Send an HTTP request to the configured endpoint and return the response.
#         :param user: A string depicting the user to send the request as.
#         :param login: Whether or not to log in before sending the request.
#         :param query_string: The query string to include in the request.
#         :param input_uuid: The UUID of the organization to request the ScanConfig of.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         self._url_parameters = str(input_uuid)
#         return self.get(query_string=query_string)
#
#     def test_auth_required(self):
#         """
#         Tests that this API endpoint requires authentication for invocation.
#         :return: None
#         """
#         org = self.__create_organization_for_user()
#         response = self.__send_request(login=False, input_uuid=org.uuid)
#         org.delete()
#         self.assert_request_requires_auth(response)
#
#     def test_regular_user_retrieve_owned_succeeds(self):
#         """
#         Tests that requesting the API endpoint for an organization owned by the given user succeeds.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         response = self.__send_request(user="user_1", input_uuid=org.uuid)
#         org.delete()
#         self.assert_request_succeeds(response)
#
#     def test_regular_user_retrieve_not_owned_fails(self):
#         """
#         Tests that requesting the API endpoint for an organization not owned by the given user fails.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_2")
#         response = self.__send_request(user="user_1", input_uuid=org.uuid)
#         org.delete()
#         self.assert_request_not_found(response)
#
#     def test_retrieve_unknown_uuid_fails(self):
#         """
#         Tests that requesting the API endpoint with a random UUID fails.
#         :return: None
#         """
#         self.assert_request_not_found(self.__send_request(input_uuid=str(uuid4())))
#
#     def test_admin_user_retrieve_owned_succeeds(self):
#         """
#         Tests that requesting the API endpoint as an admin user for an org owned by the given user succeeds.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="admin_1")
#         response = self.__send_request(user="admin_1", input_uuid=org.uuid)
#         org.delete()
#         self.assert_request_succeeds(response)
#
#     def test_admin_user_retrieve_not_owned_succeeds(self):
#         """
#         Tests that requesting the API endpoint as an admin user for an organization not owned by the user
#         succeeds.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         response = self.__send_request(user="admin_1", input_uuid=org.uuid)
#         org.delete()
#         self.assert_request_succeeds(response)
#
#     def test_retrieve_no_scan_config_fails(self):
#         """
#         Tests that requesting the API endpoint as a regular user for an organization that does not have a
#         ScanConfig associated with it fails.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         org.scan_config.delete()
#         response = self.__send_request(user="user_1", input_uuid=org.uuid)
#         org.delete()
#         self.assert_request_not_found(response)
#
#
# class TestSetOrganizationScanConfig(
#     ParameterizedRouteMixin,
#     WsDjangoViewTestCase,
# ):
#     """
#     This is a test case for testing the set_organization_scan_config function APIView.
#     """
#
#     _api_route = "/organizations/%s/scan-config/set/"
#     _url_parameters = None
#
#     def __create_organization_for_user(self, user_string="user_1"):
#         user = self.get_user(user=user_string)
#         org = rest.models.Organization.objects.create(name="Name", description="Description")
#         org.add_admin_user(user)
#         org.save()
#         return org
#
#     def __send_set_request(
#             self,
#             user="user_1",
#             login=True,
#             query_string=None,
#             scan_config_uuid=None,
#             org_uuid=None,
#             include_scan_config_uuid=True,
#     ):
#         """
#         Send a request to the API endpoint and return the response.
#         :param user: A string depicting the user to send the request as.
#         :param login: Whether or not to log in before sending the request.
#         :param query_string: The query string to include in the request.
#         :param scan_config_uuid: The UUID of the ScanConfig to set the organization's ScanConfig to.
#         :param org_uuid: The UUID of the organization to set the ScanConfig of.
#         :param include_scan_config_uuid: Whether or not to include the ScanConfig UUID in the request.
#         :return: The HTTP response.
#         """
#         if login:
#             self.login(user=user)
#         to_send = {}
#         if include_scan_config_uuid:
#             to_send["scan_config"] = str(scan_config_uuid)
#         self._url_parameters = str(org_uuid)
#         return self.post(query_string=query_string, data=to_send)
#
#     def test_requires_auth(self):
#         """
#         Tests that the API endpoint requires authentication.
#         :return: None
#         """
#         self.assert_request_requires_auth(self.__send_set_request(login=False))
#
#     def test_regular_user_set_owned_config_success_status(self):
#         """
#         Tests that submitting a set request to a ScanConfig available to the requesting user succeeds.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         scan_config = self.get_default_scan_config()
#         response = self.__send_set_request(user="user_1", org_uuid=org.uuid, scan_config_uuid=scan_config.uuid)
#         org.delete()
#         self.assert_request_succeeds(response)
#
#     def test_regular_user_set_owned_config_sets(self):
#         """
#         Tests that submitting a set request to the ScanConfig available to the requesting user successfully
#         sets the ScanConfig for the organization.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         scan_config = self.get_default_scan_config()
#         response = self.__send_set_request(user="user_1", org_uuid=org.uuid, scan_config_uuid=scan_config.uuid)
#         org.delete()
#         self.assertEqual(response.json()["name"], scan_config.name)
#
#     def test_regular_user_not_owned_org_fails(self):
#         """
#         Tests that submitting a set request for an organization that the requesting regular user does not have
#         permissions for fails.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_2")
#         scan_config = self.get_default_scan_config()
#         response = self.__send_set_request(user="user_1", org_uuid=org.uuid, scan_config_uuid=scan_config.uuid)
#         org.delete()
#         self.assert_request_not_found(response)
#
#     def test_regular_user_unknown_org_fails(self):
#         """
#         Tests that submitting a set request with a random organization UUID fails.
#         :return: None
#         """
#         scan_config = self.get_default_scan_config()
#         self.assert_request_not_found(self.__send_set_request(
#             user="user_1",
#             org_uuid=str(uuid4()),
#             scan_config_uuid=scan_config.uuid,
#         ))
#
#     def test_admin_user_not_owned_org_succeeds(self):
#         """
#         Tests that submitting a set request on behalf of an administrative user for an organization they do
#         not own succeeds.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         scan_config = self.get_default_scan_config()
#         response = self.__send_set_request(user="admin_1", scan_config_uuid=scan_config.uuid, org_uuid=org.uuid)
#         org.delete()
#         self.assert_request_succeeds(response)
#
#     def test_regular_user_not_admin_role_fails(self):
#         """
#         Tests that submitting a set request on behalf of a regular user that does not have administrative
#         permissions for the organization fails.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         user = self.get_user(user="user_1")
#         org.set_user_permissions(user=user, permission_level="scan")
#         scan_config = self.get_default_scan_config()
#         response = self.__send_set_request(user="user_1", org_uuid=org.uuid, scan_config_uuid=scan_config.uuid)
#         org.delete()
#         self.assert_request_not_found(response)
#
#     def test_no_scan_config_uuid_fails(self):
#         """
#         Tests that submitting a request and omitting a ScanConfig UUID fails.
#         :return: None
#         """
#         org = self.__create_organization_for_user()
#         response = self.__send_set_request(org_uuid=org.uuid, include_scan_config_uuid=False, query_string="FOO=BAR")
#         org.delete()
#         self.assert_request_fails(response)
#
#     def test_empty_scan_config_uuid_fails(self):
#         """
#         Tests that submitting a request with an empty ScanConfig UUID fails.
#         :return: None
#         """
#         org = self.__create_organization_for_user()
#         response = self.__send_set_request(org_uuid=org.uuid, scan_config_uuid=None)
#         org.delete()
#         self.assert_request_fails(response)
#
#     def test_unknown_scan_config_uuid_fails(self):
#         """
#         Tests that submitting a request with a random UUID for the ScanConfig fails.
#         :return: None
#         """
#         org = self.__create_organization_for_user()
#         response = self.__send_set_request(org_uuid=org.uuid, scan_config_uuid=str(uuid4()))
#         org.delete()
#         self.assert_request_not_found(response)
#
#     def test_set_scan_config_is_default_regular_user_succeeds(self):
#         """
#         Tests that submitting a request as a regular user to set from a ScanConfig that is_default succeeds.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         scan_config = self.get_default_scan_config()
#         response = self.__send_set_request(user="user_1", org_uuid=org.uuid, scan_config_uuid=scan_config.uuid)
#         org.delete()
#         self.assert_request_succeeds(response)
#
#     def test_set_scan_config_is_owned_regular_user_succeeds(self):
#         """
#         Tests that submitting a request as a regular user to set from a ScanConfig that is attached to the
#         requesting user succeeds.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         scan_config = self.get_scan_config_for_user(user="user_1")
#         response = self.__send_set_request(user="user_1", org_uuid=org.uuid, scan_config_uuid=scan_config.uuid)
#         org.delete()
#         self.assert_request_succeeds(response)
#
#     def test_set_scan_config_org_assoc_regular_user_succeeds(self):
#         """
#         Tests that submitting a request as a regular user to set from a ScanConfig that is associated with
#         an organization that the requesting user has read permissions on succeeds.
#         :return: None
#         """
#         org = self.__create_organization_for_user(user_string="user_1")
#         scan_config = org.scan_config
#         response = self.__send_set_request(user="user_1", org_uuid=org.uuid, scan_config_uuid=scan_config.uuid)
#         org.delete()
#         self.assert_request_succeeds(response)
#
#     def test_set_scan_config_not_owned_regular_user_fails(self):
#         """
#         Tests that submitting a request as a regular user to set from a ScanConfig that they do not have
#         permissions for fails.
#         :return: None
#         """
#         user_org = self.__create_organization_for_user(user_string="user_1")
#         other_org = self.__create_organization_for_user(user_string="user_2")
#         scan_config = other_org.scan_config
#         response = self.__send_set_request(user="user_1", org_uuid=user_org.uuid, scan_config_uuid=scan_config.uuid)
#         user_org.delete()
#         other_org.delete()
#         self.assert_request_not_found(response)
#
#     def test_set_scan_config_not_owned_admin_user_succeeds(self):
#         """
#         Tests that submitting a request as an administrative user to set from a ScanConfig that they do not have
#         ownership of succeeds.
#         :return: None
#         """
#         user_org = self.__create_organization_for_user(user_string="user_1")
#         other_org = self.__create_organization_for_user(user_string="user_2")
#         scan_config = other_org.scan_config
#         response = self.__send_set_request(user="admin_1", org_uuid=user_org.uuid, scan_config_uuid=scan_config.uuid)
#         user_org.delete()
#         other_org.delete()
#         self.assert_request_succeeds(response)


class TestQuickScanOrganization(
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for the quick_scan_organization function API view..
    """

    _api_route = "/organizations/%s/quick-scan/"
    _url_parameters = None
    _original_send_emails_delay = None
    _original_handle_placed_order_delay = None

    def setUp(self):
        """
        Set up this test case by mocking out calls to task invocations.
        :return: None
        """
        super(TestQuickScanOrganization, self).setUp()
        self._original_send_emails_delay = send_emails_for_placed_order.delay
        send_emails_for_placed_order.delay = MagicMock()
        self._original_handle_placed_order_delay = handle_placed_order.delay
        handle_placed_order.delay = MagicMock()

    def tearDown(self):
        """
        Tear down this test case by replacing task invocation mocks with their original
        values.
        :return: None
        """
        send_emails_for_placed_order.delay = self._original_send_emails_delay
        handle_placed_order.delay = self._original_handle_placed_order_delay
        super(TestQuickScanOrganization, self).tearDown()

    def __send_quick_scan_request(
            self,
            user="user_1",
            login=True,
            query_string=None,
            input_uuid="POPULATE",
            include_scan_config_uuid=True,
            scan_config_uuid="POPULATE",
            include_scan_config=True,
            scan_config_empty=False,
            include_name=True,
            name="name",
            include_description=True,
            description="description",
            include_is_default=True,
            is_default=False,
            include_saved_for_later=True,
            saved_for_later=False,
            include_scan_domain_names=True,
            scan_domain_names=True,
            include_scan_network_ranges=True,
            scan_network_ranges=True,
            include_scan_ip_addresses=True,
            scan_ip_addresses=True,
            include_scan_network_services=True,
            scan_network_services=True,
            include_scan_ssl_support=True,
            scan_ssl_support=True,
            include_dns_enumerate_subdomains=True,
            dns_enumerate_subdomains=False,
            include_dns_scan_resolutions=True,
            dns_scan_resolutions=True,
            include_network_scan_bandwidth=True,
            network_scan_bandwidth="10M",
            include_network_inspect_live_hosts=True,
            network_inspect_live_hosts=True,
            include_ip_address_geolocate=True,
            ip_address_geolocate=True,
            include_ip_address_reverse_hostname=True,
            ip_address_reverse_hostname=True,
            include_ip_address_historic_dns=True,
            ip_address_historic_dns=True,
            include_ip_address_as_data=True,
            ip_address_as_data=False,
            include_ip_address_whois_data=True,
            ip_address_whois_data=False,
            include_network_service_check_liveness=True,
            network_service_check_liveness=True,
            include_network_service_fingerprint=True,
            network_service_fingerprint=True,
            include_network_service_inspect_app=True,
            network_service_inspect_app=True,
            include_ssl_enumerate_vulns=True,
            ssl_enumerate_vulns=True,
            include_ssl_enumerate_cipher_suites=True,
            ssl_enumerate_cipher_suites=True,
            include_ssl_retrieve_cert=True,
            ssl_retrieve_cert=True,
            include_app_inspect_web_app=True,
            app_inspect_web_app=True,
            include_web_app_include_http_on_https=True,
            web_app_include_http_on_https=True,
            include_web_app_enum_vhosts=True,
            web_app_enum_vhosts=True,
            include_web_app_take_screenshot=True,
            web_app_take_screenshot=True,
            include_web_app_do_crawling=True,
            web_app_do_crawling=False,
            include_web_app_enum_user_agents=True,
            web_app_enum_user_agents=False,
            include_completion_web_hook_url=True,
            completion_web_hook_url="http://www.foo.com",
            include_completion_email_org_users=True,
            completion_email_org_users=True,
            include_completion_email_order_user=True,
            completion_email_order_user=True,
            include_scan_ports=True,
            scan_ports=[{"port_number": 22, "protocol": "tcp"}],
            include_dns_record_types=True,
            dns_record_types=[{"record_type": "A"}],
            include_targets=True,
            targets=["8.8.8.8", "www.foo.com"],
            include_completion_web_hook_url_override=True,
            completion_web_hook_url_override="http://www.woot.com",
            include_completion_email_org_users_override=True,
            completion_email_org_users_override=True,
            include_completion_email_order_user_override=True,
            completion_email_order_user_override=True,
    ):
        """
        Send a request to the endpoint to kick off a quick scan of the referenced organization.
        :param user: The user to submit the request as.
        :param login: Whether or not to log the user in prior to sending the request.
        :param query_string: The query string to submit alongside the URL.
        :param input_uuid: The UUID of the organization to request a quick scan for.
        :param include_scan_config_uuid: Whether or not to include the ScanConfig UUID.
        :param scan_config_uuid: The UUID of the ScanConfig to include.
        :param include_scan_config: Whether or not to include the ScanConfig in the request.
        :param scan_config_empty: Whether or not to have the ScanConfig be empty in the request.
        :param include_name: Whether or not to include the WHAT parameter in the request.
        :param name: A name to associate with this scanning configuration.
        :param include_description: Whether or not to include the description parameter in the request.
        :param description: A brief description about what this scanning configuration entails.
        :param include_is_default: Whether or not to include the is_default parameter in the request.
        :param is_default: Whether or not this scanning configuration is one of the default configurations provided by
        Web Sight.
        :param include_saved_for_later: Whether or not to include the saved_for_later parameter in the request.
        :param saved_for_later: Whether or not this scanning configuration should be saved as a configuration that can
        be used in future scans.
        :param include_scan_domain_names: Whether or not to include the scan_domain_names parameter in the request.
        :param scan_domain_names: Whether or not to scan domain names associated with the scan.
        :param include_scan_network_ranges: Whether or not to include the scan_network_ranges parameter in the request.
        :param scan_network_ranges: Whether or not to scan network ranges associated with the scan.
        :param include_scan_ip_addresses: Whether or not to include the scan_ip_addresses parameter in the request.
        :param scan_ip_addresses: Whether or not to gather information about individual IP addresses.
        :param include_scan_network_services: Whether or not to include the scan_network_services parameter in the
        request.
        :param scan_network_services: Whether or not to gather information about individual network services.
        :param include_scan_ssl_support: Whether or not to include the scan_ssl_support parameter in the request.
        :param scan_ssl_support: Whether or not to gather information about SSL supporting services.
        :param include_dns_enumerate_subdomains: Whether or not to include the dns_enumerate_subdomains parameter in
        the request.
        :param dns_enumerate_subdomains: Whether or not to enumerate subdomains.
        :param include_dns_scan_resolutions: Whether or not to include the dns_scan_resolutions parameter in the
        request.
        :param dns_scan_resolutions: Whether or not to scan IP addresses associated with domain name resolutions.
        :param include_network_scan_bandwidth: Whether or not to include the network_scan_bandwidth parameter in the
        request.
        :param network_scan_bandwidth: The maximum bandwidth to throttle Zmap scans at.
        :param include_network_inspect_live_hosts: Whether or not to include the network_inspect_live_hosts parameter
        in the request.
        :param network_inspect_live_hosts: Whether or not to continue gathering host-specific information when a host
        is found to be alive as a result of network discovery.
        :param include_ip_address_geolocate: Whether or not to include the ip_address_geolocate parameter in the
        request.
        :param ip_address_geolocate: Whether or not to geolocate IP addresses.
        :param include_ip_address_reverse_hostname: Whether or not to include the ip_address_reverse_hostname parameter
        in the request.
        :param ip_address_reverse_hostname: Whether or not to retrieve reverse hostname data for IP addresses.
        :param include_ip_address_historic_dns: Whether or not to include the ip_address_historic_dns parameter in
        the request.
        :param ip_address_historic_dns: Whether or not to retrieve historic DNS data for IP addresses.
        :param include_ip_address_as_data: Whether or not to include the ip_address_as_data parameter in the request.
        :param ip_address_as_data: Whether or not toint retrieve data about IP addresses' autonomous systems.
        :param include_ip_address_whois_data: Whether or not to include the ip_address_whois_data parameter in the
        request.
        :param ip_address_whois_data: Whether or not to retrieve WHOIS data about an IP address.
        :param include_network_service_check_liveness: Whether or not to include the network_service_check_liveness
        parameter in the request.
        :param network_service_check_liveness: Whether or not to check for network service liveness.
        :param include_network_service_fingerprint: Whether or not to include the network_service_fingerprint parameter
        in the request.
        :param network_service_fingerprint: Whether or not to fingerprint the applications found on live network
        services.
        :param include_network_service_inspect_app: Whether or not to include the network_service_inspect_app
        parameter in the request.
        :param network_service_inspect_app: Whether or not to inspect applications found on live network services.
        :param include_ssl_enumerate_vulns: Whether or not to include the ssl_enumerate_vulns parameter in the request.
        :param ssl_enumerate_vulns: Whether or not to enumerate the presence of vulnerabilities in SSL services.
        :param include_ssl_enumerate_cipher_suites: Whether or not to include the ssl_enumerate_cipher_suites
        parameter in the request.
        :param ssl_enumerate_cipher_suites: Whether or not to enumerate the supported cipher suites found within an
        SSL service.
        :param include_ssl_retrieve_cert: Whether or not to include the ssl_retrieve_cert parameter in the request.
        :param ssl_retrieve_cert: Whether or not to retrieve the certificate presented by an SSL supporting service.
        :param include_app_inspect_web_app: Whether or not to include the app_inspect_web_app parameter in the request.
        :param app_inspect_web_app: Whether or not to inspect discovered web applications.
        :param include_web_app_include_http_on_https: Whether or not to include the web_app_include_http_on_https
        parameter in the request.
        :param web_app_include_http_on_https: Whether or not to inspect HTTP services that are hosted on the same IP
        address and port as HTTPS services.
        :param include_web_app_enum_vhosts: Whether or not to include the web_app_enum_vhosts parameter in the request.
        :param web_app_enum_vhosts: Whether or not to enumerate virtual hosts for web servers.
        :param include_web_app_take_screenshot: Whether or not to include the web_app_take_screenshot parameter in
        the request.
        :param web_app_take_screenshot: Whether or not to take screenshots of web applications.
        :param include_web_app_do_crawling: Whether or not to include the web_app_do_crawling parameter in the request.
        :param web_app_do_crawling: Whether or not to crawl web applications or just retrieve the landing page resource.
        :param include_web_app_enum_user_agents: Whether or not to include the web_app_enum_user_agents parameter in
        the request.
        :param web_app_enum_user_agents: Whether or not to gather information about user agent responses for a web
        application.
        :param include_completion_web_hook_url: Whether or not to include the completion_web_hook_url parameter.
        :param completion_web_hook_url: The value to submit as the web hook callback to hit once the order has
        completed.
        :param include_completion_email_org_users: Whether or not to include the completion_email_org_users parameter.
        :param completion_email_org_users: Whether or not to send an email to all organization users when the order
        has completed.
        :param include_completion_email_order_user: Whether or not to include the completion_email_order_user 
        parameter.
        :param completion_email_order_user: Whether or not to send an email to the invoking user once the order has
        completed.
        :param include_scan_ports: Whether or not to include the ScanPort objects in the ScanConfig.
        :param scan_ports: A list of dictionaries depicting ScanPort objects to include in the request.
        :param include_dns_record_types: Whether or not to include the DnsRecordType objects in the ScanConfig.
        :param dns_record_types: A list of dictionaries depicting the DnsRecordType objects to include in the request.
        :param include_targets: Whether or not to include targets in the request.
        :param targets: The targets to include in the request.
        :param include_completion_web_hook_url_override: Whether or not to include the completion_web_hook_url override
        parameter.
        :param completion_web_hook_url_override: The completion_web_hook_url override value.
        :param include_completion_email_org_users_override: Whether or not to include the completion_email_org_users
        parameter.
        :param completion_email_org_users_override: The completion_email_org_users override value.
        :param include_completion_email_order_user_override: Whether or not to include the completion_email_order_user
        override value.
        :param completion_email_order_user_override: The completion_email_order_user override value.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            organization = self.get_organization_for_user(user=user)
            input_uuid = organization.uuid
        self._url_parameters = str(input_uuid)
        to_send = {}
        if include_scan_config_uuid:
            if scan_config_uuid == "POPULATE":
                scan_config = self.get_scan_config_for_user(user=user)
                to_send["scan_config_uuid"] = str(scan_config.uuid)
            else:
                to_send["scan_config_uuid"] = scan_config_uuid
        if include_scan_config:
            if scan_config_empty:
                to_send["scan_config"] = None
            else:
                scan_config = {}
                if include_name:
                    scan_config["name"] = name
                if include_description:
                    scan_config["description"] = description
                if include_is_default:
                    scan_config["is_default"] = is_default
                if include_saved_for_later:
                    scan_config["saved_for_later"] = saved_for_later
                if include_scan_domain_names:
                    scan_config["scan_domain_names"] = scan_domain_names
                if include_scan_network_ranges:
                    scan_config["scan_network_ranges"] = scan_network_ranges
                if include_scan_ip_addresses:
                    scan_config["scan_ip_addresses"] = scan_ip_addresses
                if include_scan_network_services:
                    scan_config["scan_network_services"] = scan_network_services
                if include_scan_ssl_support:
                    scan_config["scan_ssl_support"] = scan_ssl_support
                if include_dns_enumerate_subdomains:
                    scan_config["dns_enumerate_subdomains"] = dns_enumerate_subdomains
                if include_dns_scan_resolutions:
                    scan_config["dns_scan_resolutions"] = dns_scan_resolutions
                if include_network_scan_bandwidth:
                    scan_config["network_scan_bandwidth"] = network_scan_bandwidth
                if include_network_inspect_live_hosts:
                    scan_config["network_inspect_live_hosts"] = network_inspect_live_hosts
                if include_ip_address_geolocate:
                    scan_config["ip_address_geolocate"] = ip_address_geolocate
                if include_ip_address_reverse_hostname:
                    scan_config["ip_address_reverse_hostname"] = ip_address_reverse_hostname
                if include_ip_address_historic_dns:
                    scan_config["ip_address_historic_dns"] = ip_address_historic_dns
                if include_ip_address_as_data:
                    scan_config["ip_address_as_data"] = ip_address_as_data
                if include_ip_address_whois_data:
                    scan_config["ip_address_whois_data"] = ip_address_whois_data
                if include_network_service_check_liveness:
                    scan_config["network_service_check_liveness"] = network_service_check_liveness
                if include_network_service_fingerprint:
                    scan_config["network_service_fingerprint"] = network_service_fingerprint
                if include_network_service_inspect_app:
                    scan_config["network_service_inspect_app"] = network_service_inspect_app
                if include_ssl_enumerate_vulns:
                    scan_config["ssl_enumerate_vulns"] = ssl_enumerate_vulns
                if include_ssl_enumerate_cipher_suites:
                    scan_config["ssl_enumerate_cipher_suites"] = ssl_enumerate_cipher_suites
                if include_ssl_retrieve_cert:
                    scan_config["ssl_retrieve_cert"] = ssl_retrieve_cert
                if include_app_inspect_web_app:
                    scan_config["app_inspect_web_app"] = app_inspect_web_app
                if include_web_app_include_http_on_https:
                    scan_config["web_app_include_http_on_https"] = web_app_include_http_on_https
                if include_web_app_enum_vhosts:
                    scan_config["web_app_enum_vhosts"] = web_app_enum_vhosts
                if include_web_app_take_screenshot:
                    scan_config["web_app_take_screenshot"] = web_app_take_screenshot
                if include_web_app_do_crawling:
                    scan_config["web_app_do_crawling"] = web_app_do_crawling
                if include_web_app_enum_user_agents:
                    scan_config["web_app_enum_user_agents"] = web_app_enum_user_agents
                if include_completion_web_hook_url:
                    scan_config["completion_web_hook_url"] = completion_web_hook_url
                if include_completion_email_org_users:
                    scan_config["completion_email_org_users"] = completion_email_org_users
                if include_completion_email_order_user:
                    scan_config["completion_email_order_user"] = completion_email_order_user
                if include_scan_ports:
                    scan_config["scan_ports"] = scan_ports
                if include_dns_record_types:
                    scan_config["dns_record_types"] = dns_record_types
                to_send["scan_config"] = scan_config
        if include_targets:
            to_send["targets"] = targets
        if include_completion_web_hook_url_override:
            to_send["completion_web_hook_url"] = completion_web_hook_url_override
        if include_completion_email_org_users_override:
            to_send["completion_email_org_users"] = completion_email_org_users_override
        if include_completion_email_order_user_override:
            to_send["completion_email_order_user"] = completion_email_order_user_override
        return self.post(query_string=query_string, data=to_send)

    def test_submit_regular_user_succeeds(self):
        """
        Tests that submitting a valid request to the endpoint as a regular user returns the expected HTTP
        status code.
        :return: None
        """
        self.assert_request_succeeds(self.__send_quick_scan_request(user="user_1"), status_code=201)

    def test_submit_admin_user_succeeds(self):
        """
        Tests that submitting a valid request to the endpoint as an administrative user returns the expected HTTP
        status code.
        :return: None
        """
        self.assert_request_succeeds(self.__send_quick_scan_request(user="admin_1"), status_code=201)

    def test_requires_auth(self):
        """
        Tests that the API endpoint requires authentication.
        :return: None
        """
        self.assert_request_requires_auth(self.__send_quick_scan_request(login=False))

    def test_unknown_organization_fails(self):
        """
        Tests that sending a request to the endpoint with a random UUID for the organization UUID fails.
        :return: None
        """
        self.assert_request_not_found(self.__send_quick_scan_request(input_uuid=str(uuid4())))

    def test_regular_user_cannot_scan_fails(self):
        """
        Tests that sending a request to the endpoint with the UUID of an organization that the requesting
        user does not have scan permissions for fails.
        :return: None
        """
        org = self.get_organization_for_user(user="user_1")
        user = self.get_user(user="user_1")
        org.set_user_permissions(user=user, permission_level="write")
        response = self.__send_quick_scan_request(user="user_1")
        org.set_user_permissions(user=user, permission_level="admin")
        self.assert_request_not_authorized(response)

    def test_admin_user_cannot_scan_succeeds(self):
        """
        Tests that sending a request to the endpoint with the UUID of the organization that the requesting
        user does not have scan permission for succeeds when the requesting user is a superuser.
        :return: None
        """
        org = self.get_organization_for_user(user="admin_1")
        user = self.get_user(user="admin_1")
        org.set_user_permissions(user=user, permission_level="write")
        response = self.__send_quick_scan_request(user="admin_1")
        org.set_user_permissions(user=user, permission_level="admin")
        self.assert_request_succeeds(response, status_code=201)

    def test_no_scan_config_uuid_succeeds(self):
        """
        Tests that sending a request to the endpoint and omitting the scan_config_uuid parameter succeeds.
        :return: None
        """
        self.assert_request_succeeds(self.__send_quick_scan_request(include_scan_config_uuid=False), status_code=201)

    def test_no_scan_config_succeeds(self):
        """
        Tests that sending a request to the endpoint and omitting the scan_config parameter succeeds.
        :return: None
        """
        self.assert_request_succeeds(self.__send_quick_scan_request(include_scan_config=False), status_code=201)

    def test_no_targets_fails(self):
        """
        Tests that sending a request to the endpoint and omitting the targets parameter fails.
        :return: None
        """
        self.assert_request_fails(self.__send_quick_scan_request(include_targets=False))

    def test_no_completion_web_hook_url_succeeds(self):
        """
        Tests that sending a request to the endpoint and omitting the completion_web_hook_url parameter succeeds.
        :return: None
        """
        self.assert_request_succeeds(
            self.__send_quick_scan_request(include_completion_email_order_user_override=False),
            status_code=201,
        )

    def test_no_completion_email_org_users_succeeds(self):
        """
        Tests that sending a request to the endpoint and omitting the completion_email_org_users parameter succeeds.
        :return: None
        """
        self.assert_request_succeeds(
            self.__send_quick_scan_request(include_completion_email_org_users_override=False),
            status_code=201,
        )

    def test_no_completion_email_order_user_succeeds(self):
        """
        Tests that sending a request to the endpoint and omitting the completion_email_order_user parameter succeeds.
        :return: None
        """
        self.assert_request_succeeds(
            self.__send_quick_scan_request(include_completion_email_order_user_override=False),
            status_code=201,
        )

    def test_unknown_scan_config_uuid_fails(self):
        """
        Tests that sending a request to the endpoint and providing a random UUID for the scan_config_uuid parameter
        fails.
        :return: None
        """
        self.assert_request_not_found(self.__send_quick_scan_request(scan_config_uuid=str(uuid4())))

    def test_not_owned_scan_config_uuid_regular_user_fails(self):
        """
        Tests that sending a request to the endpoint and providing the UUID of the ScanConfig that the requesting
        regular user does not have permission to access fails.
        :return: None
        """
        scan_config = self.get_scan_config_for_user(user="user_2")
        self.assert_request_not_found(self.__send_quick_scan_request(
            user="user_1",
            scan_config_uuid=scan_config.uuid,
        ))

    def test_not_owned_scan_config_uuid_admin_user_succeeds(self):
        """
        Tests that sending a request to the endpoint and providing the UUID of the ScanConfig that the requesting
        admin user does not have permission to access succeeds.
        :return: None
        """
        scan_config = self.get_scan_config_for_user(user="user_2")
        self.assert_request_succeeds(
            self.__send_quick_scan_request(
                user="admin_1",
                scan_config_uuid=scan_config.uuid,
            ),
            status_code=201,
        )

    def test_scan_config_uuid_assigns_correct_scan_config(self):
        """
        Tests that sending a request containing a valid scan_config_uuid value assigns the proper ScanConfig to the
        resulting order.
        :return: None
        """
        scan_config = self.get_scan_config_for_user(user="user_1")
        original_name = scan_config.name
        scan_config.name = "LOLOLOLLLLL"
        scan_config.save()
        response = self.__send_quick_scan_request(user="user_1", scan_config_uuid=scan_config.uuid)
        scan_config.name = original_name
        scan_config.save()
        new_order = rest.models.Order.objects.get(pk=response.json()["order_uuid"])
        self.assertEqual(new_order.scan_config.name, "LOLOLOLLLLL")

    def test_scan_config_data_succeeds(self):
        """
        Tests that sending a request containing valid scan_config data succeeds.
        :return: None
        """
        self.assert_request_succeeds(self.__send_quick_scan_request(scan_config_uuid=None), status_code=201)

    def test_scan_config_data_assigns_correct_scan_config(self):
        """
        Tests that sending a request containing valid scan_config data assigns the proper ScanConfig to the resulting
        order.
        :return: None
        """
        response = self.__send_quick_scan_request(scan_config_uuid=None, name="LOLLERCOPTER")
        new_order = rest.models.Order.objects.get(pk=response.json()["order_uuid"])
        self.assertEqual(new_order.scan_config.name, "LOLLERCOPTER")

    def test_no_scan_config_uuid_or_data_succeeds(self):
        """
        Tests that sending a request omitting both scan_config and scan_config_uuid succeeds.
        :return: None
        """
        self.assert_request_succeeds(
            self.__send_quick_scan_request(scan_config_uuid=None, scan_config_empty=True),
            status_code=201,
        )

    def test_no_scan_config_uuid_or_data_assigns_correct_scan_config(self):
        """
        Tests that sending a request omitting both scan_config and scan_config_uuid assigns the proper ScanConfig
        to the resulting order.
        :return: None
        """
        org = self.get_organization_for_user(user="user_1")
        original_name = org.scan_config.name
        org.scan_config.name = "LOLLERCOPTER"
        org.scan_config.save()
        response = self.__send_quick_scan_request(
            user="user_1",
            input_uuid=org.uuid,
            scan_config_uuid=None,
            scan_config_empty=True,
        )
        org.scan_config.name = original_name
        org.scan_config.save()
        new_order = rest.models.Order.objects.get(pk=response.json()["order_uuid"])
        self.assertEqual(new_order.scan_config.name, "LOLLERCOPTER")

    def test_success_creates_new_scan_config(self):
        """
        Tests that a successful request will create a new ScanConfig in the back-end database.
        :return: None
        """
        first_count = rest.models.ScanConfig.objects.count()
        self.__send_quick_scan_request()
        second_count = rest.models.ScanConfig.objects.count()
        self.assertEqual(second_count, first_count + 1)

    def test_all_domain_targets_succeeds(self):
        """
        Tests that submitting a request with only domain names as targets succeeds.
        :return: None
        """
        self.assert_request_succeeds(
            self.__send_quick_scan_request(targets=["foo.bar.com", "foo.baz.com"]),
            status_code=201,
        )

    def test_all_network_range_targets_succeeds(self):
        """
        Tests that submitting a request with only network ranges as targets succeeds.
        :return: None
        """
        self.assert_request_succeeds(
            self.__send_quick_scan_request(targets=["8.8.8.8/24", "9.9.9.9/24"]),
            status_code=201,
        )

    def test_all_ip_address_targets_succeeds(self):
        """
        Tests that submitting a request with only IP addresses as targets succeeds.
        :return: None
        """
        self.assert_request_succeeds(
            self.__send_quick_scan_request(targets=["8.8.8.8", "9.9.9.9"]),
            status_code=201,
        )

    def test_domain_name_target_creates_order_domain(self):
        """
        Tests that submitting a request with a domain name target successfully creates the expected
        OrderDomainName.
        :return: None
        """
        first_count = rest.models.OrderDomainName.objects.count()
        self.__send_quick_scan_request(targets=["www.foo.com"])
        second_count = rest.models.OrderDomainName.objects.count()
        self.assertEqual(second_count, first_count + 1)

    def test_domain_name_target_wires_order_domain(self):
        """
        Tests that submitting a request with a domain name target successfully wires up the OrderDomainName
        to the expected models.
        :return: None
        """
        self.__send_quick_scan_request(targets=["www.foo.com"])
        new_order_domain = self.get_last_created(rest.models.OrderDomainName)
        self.assertTrue(all([new_order_domain.order, new_order_domain.domain_name]))

    def test_network_range_target_created_order_network(self):
        """
        Tests that submitting a request with a network target successfully creates the expected OrderNetwork.
        :return: None
        """
        first_count = rest.models.OrderNetwork.objects.count()
        self.__send_quick_scan_request(targets=["8.8.8.8/24"])
        second_count = rest.models.OrderNetwork.objects.count()
        self.assertEqual(second_count, first_count + 1)

    def test_network_range_target_wires_order_network(self):
        """
        Tests that submitting a request with a network target successfully wires up the OrderNetwork to the
        expected models.
        :return: None
        """
        self.__send_quick_scan_request(targets=["8.8.8.8/24"])
        new_order_network = self.get_last_created(rest.models.OrderNetwork)
        self.assertTrue(all([new_order_network.network, new_order_network.order]))

    def test_ip_address_target_creates_order_network(self):
        """
        Tests that submitting a request with an IP address target successfully creates the expected OrderNetwork.
        :return: None
        """
        first_count = rest.models.OrderNetwork.objects.count()
        self.__send_quick_scan_request(targets=["8.8.8.8"])
        second_count = rest.models.OrderNetwork.objects.count()
        self.assertEqual(second_count, first_count + 1)

    def test_ip_address_target_wires_order_network(self):
        """
        Tests that submitting a request with an IP address target successfully wires up the OrderNetwork to the
        expected models.
        :return: None
        """
        self.__send_quick_scan_request(targets=["8.8.8.8"])
        new_order_network = self.get_last_created(rest.models.OrderNetwork)
        self.assertTrue(all([new_order_network.network, new_order_network.order]))

    def test_empty_targets_list_fails(self):
        """
        Tests that submitting a request with an empty targets list fails.
        :return: None
        """
        self.assert_request_fails(self.__send_quick_scan_request(targets=[]))

    def test_invalid_targets_list_fails(self):
        """
        Tests that submitting a request with only invalid targets fails.
        :return: None
        """
        self.assert_request_fails(self.__send_quick_scan_request(targets=["____", "****"]))

    def test_completion_web_hook_url_overwrites(self):
        """
        Tests that submitting a request with a competion_web_hook_url parameter overrides the default value in
        the related ScanConfig.
        :return: None
        """
        scan_config = self.get_scan_config_for_user(user="user_1")
        original_web_hook = scan_config.completion_web_hook_url
        scan_config.completion_web_hook_url = "http://www.lala.com"
        scan_config.save()
        response = self.__send_quick_scan_request(
            user="user_1",
            scan_config_uuid=scan_config.uuid,
            completion_web_hook_url_override="http://www.fafa.com",
        )
        scan_config.completion_web_hook_url = original_web_hook
        scan_config.save()
        new_order = rest.models.Order.objects.get(pk=response.json()["order_uuid"])
        self.assertEqual(new_order.scan_config.completion_web_hook_url, "http://www.fafa.com")

    def test_completion_email_org_users_overwrites(self):
        """
        Tests that submitting a request with a completion_email_org_users parameter overrides the default value in
        the related ScanConfig.
        :return: None
        """
        scan_config = self.get_scan_config_for_user(user="user_1")
        original_email_org = scan_config.completion_email_org_users
        scan_config.completion_email_org_users = False
        scan_config.save()
        response = self.__send_quick_scan_request(
            user="user_1",
            scan_config_uuid=scan_config.uuid,
            completion_email_org_users_override=True,
        )
        scan_config.completion_email_org_users = original_email_org
        scan_config.save()
        new_order = rest.models.Order.objects.get(pk=response.json()["order_uuid"])
        self.assertTrue(new_order.scan_config.completion_email_org_users)

    def test_completion_email_order_user_overwrites(self):
        """
        Tests that submitting a request with a completion_email_order_user parameter overrides the default value in
        the related ScanConfig.
        :return: None
        """
        scan_config = self.get_scan_config_for_user(user="user_1")
        original_email_user = scan_config.completion_email_order_user
        scan_config.completion_email_order_user = False
        scan_config.save()
        response = self.__send_quick_scan_request(
            user="user_1",
            scan_config_uuid=scan_config.uuid,
            completion_email_order_user_override=True,
        )
        scan_config.completion_email_order_user = original_email_user
        scan_config.save()
        new_order = rest.models.Order.objects.get(pk=response.json()["order_uuid"])
        self.assertTrue(new_order.scan_config.completion_email_order_user)

    def test_no_targets_creates_no_scan_config(self):
        """
        Tests that an invalid request that contains no valid targets does not create a new ScanConfig.
        :return: None
        """
        first_count = rest.models.ScanConfig.objects.count()
        self.__send_quick_scan_request(targets=[])
        second_count = rest.models.ScanConfig.objects.count()
        self.assertEqual(first_count, second_count)

    def test_no_targets_creates_no_order(self):
        """
        Tests that an invalid request that contains no valid targets does not create a new Order.
        :return: None
        """
        first_count = rest.models.Order.objects.count()
        self.__send_quick_scan_request(targets=[])
        second_count = rest.models.Order.objects.count()
        self.assertEqual(first_count, second_count)

    def test_no_targets_creates_no_order_domains(self):
        """
        Tests that an invalid request that contains no valid targets does not create any new OrderDomains.
        :return: None
        """
        first_count = rest.models.OrderDomainName.objects.count()
        self.__send_quick_scan_request(targets=[])
        second_count = rest.models.OrderDomainName.objects.count()
        self.assertEqual(first_count, second_count)

    def test_no_targets_creates_no_domain_names(self):
        """
        Tests that an invalid request that contains no valid targets does not create any new DomainNames.
        :return: None
        """
        first_count = rest.models.DomainName.objects.count()
        self.__send_quick_scan_request(targets=[])
        second_count = rest.models.DomainName.objects.count()
        self.assertEqual(first_count, second_count)

    def test_no_targets_creates_no_order_networks(self):
        """
        Tests that an invalid request that contains no valid targets does not create any new OrderNetworks.
        :return: None
        """
        first_count = rest.models.OrderNetwork.objects.count()
        self.__send_quick_scan_request(targets=[])
        second_count = rest.models.OrderNetwork.objects.count()
        self.assertEqual(first_count, second_count)

    def test_no_targets_creates_no_networks(self):
        """
        Tests that an invalid request that contains no valid targets does not create any new Networks.
        :return: None
        """
        first_count = rest.models.Network.objects.count()
        self.__send_quick_scan_request(targets=[])
        second_count = rest.models.Network.objects.count()
        self.assertEqual(first_count, second_count)

    def test_no_targets_creates_no_scan_ports(self):
        """
        Tests that an invalid request that contains no valid targets does not create any new ScanPorts.
        :return: None
        """
        first_count = rest.models.ScanPort.objects.count()
        self.__send_quick_scan_request(targets=[])
        second_count = rest.models.ScanPort.objects.count()
        self.assertEqual(first_count, second_count)

    def test_no_targets_creates_no_dns_record_types(self):
        """
        Tests that an invalid request that contains no valid targets does not create any new DnsRecordTypes.
        :return: None
        """
        first_count = rest.models.DnsRecordType.objects.count()
        self.__send_quick_scan_request(targets=[])
        second_count = rest.models.DnsRecordType.objects.count()
        self.assertEqual(first_count, second_count)

    def test_success_marks_order_as_placed(self):
        """
        Tests that a successful request marks the order as having been placed.
        :return: None
        """
        response = self.__send_quick_scan_request()
        new_order = rest.models.Order.objects.get(pk=response.json()["order_uuid"])
        self.assertTrue(new_order.has_been_placed)

    def test_success_calls_send_emails_for_placed_order(self):
        """
        Tests that a successful request calls send_emails_for_placed_order.delay.
        :return: None
        """
        self.__send_quick_scan_request()
        self.assertTrue(send_emails_for_placed_order.delay.called)

    def test_success_calls_handle_placed_order(self):
        """
        Tests that a successful request calls handle_placed_order.delay.
        :return: None
        """
        self.__send_quick_scan_request()
        self.assertTrue(handle_placed_order.delay.called)

    def test_success_status(self):
        """
        Tests that a successful request returns the expected HTTP response status code.
        :return: None
        """
        response = self.__send_quick_scan_request()
        self.assertEqual(response.status_code, 201)

    def test_success_order_uuid(self):
        """
        Tests that a successful request returns the expected order UUID.
        :return: None
        """
        response = self.__send_quick_scan_request()
        self.assertIn("order_uuid", response.json())
