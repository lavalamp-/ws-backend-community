# -*- coding: utf-8 -*-
from __future__ import absolute_import

from mock import patch, MagicMock

from lib.sqlalchemy.ops.exception import NoResultFoundError
from ...base import BaseSqlalchemyTestCase
from ....data import WsTestData
from lib.sqlalchemy import get_ip_address_for_organization, IpAddress
import lib.sqlalchemy.ops.networks


class TestGetIpAddressForOrganization(BaseSqlalchemyTestCase):
    """
    This is a test case for testing the get_ip_address_for_organization method.
    """

    def __init__(self, *args, **kwargs):
        super(TestGetIpAddressForOrganization, self).__init__(*args, **kwargs)
        self._mock_invoke_count = 0

    def __call_get_ip_address_for_organization(
            self,
            org_uuid=None,
            ip_address=WsTestData.UNUSED_IP_ADDRESS,
            address_type="ipv4",
            network_mask_length=24,
            user="user_1",
    ):
        """
        Call get_ip_address_for_organization and return the results.
        :param org_uuid: The UUID of the organization to pass to the function. If None, defaults to the UUID
        of the default organization for the given user.
        :param ip_address: The IP address to pass to the function.
        :param address_type: The type of IP address.
        :param network_mask_length: The length of the network to create if an existing network is not found
        :param user: A string depicting the user to get the IP address for.
        :return: The results of calling the function.
        """
        if org_uuid is None:
            org_uuid = self.get_organization_for_user(user=user).uuid
        return get_ip_address_for_organization(
            db_session=self.db_session,
            org_uuid=org_uuid,
            ip_address=ip_address,
            address_type=address_type,
            network_mask_length=network_mask_length,
        )

    def test_class_c_network_already_exists(self):
        """
        Tests that the method returns an IP address in the expected network range when the network
        range is a class C network.
        :return: None
        """
        network = self.create_network_for_user(address=WsTestData.UNUSED_IP_CLASS_C, mask_length=24)
        address = self.__call_get_ip_address_for_organization(ip_address=WsTestData.UNUSED_IP_ADDRESS)
        self.assertEqual(address.network, network)

    def test_class_b_network_already_exists(self):
        """
        Tests that the method returns an IP address in the expected network range when the network
        range is a class B network.
        :return: None
        """
        network = self.create_network_for_user(address=WsTestData.UNUSED_IP_CLASS_B, mask_length=16)
        address = self.__call_get_ip_address_for_organization(ip_address=WsTestData.UNUSED_IP_ADDRESS)
        self.assertEqual(address.network, network)

    def test_class_a_network_already_exists(self):
        """
        Tests that the method returns an IP address in the expected network range when the network
        range is a class A network.
        :return: None
        """
        network = self.create_network_for_user(address=WsTestData.UNUSED_IP_CLASS_A, mask_length=8)
        address = self.__call_get_ip_address_for_organization(ip_address=WsTestData.UNUSED_IP_ADDRESS)
        self.assertEqual(address.network, network)

    def test_network_already_exists_no_create(self):
        """
        Tests that the method does not create a new network when a network matching the IP address already
        exists.
        :return: None
        """
        self.create_network_for_user(address=WsTestData.UNUSED_IP_CLASS_A, mask_length=8)
        first_count = self.count_networks()
        self.__call_get_ip_address_for_organization(ip_address=WsTestData.UNUSED_IP_ADDRESS)
        second_count = self.count_networks()
        self.assertEqual(first_count, second_count)

    def test_no_result_creates_network(self):
        """
        Tests that the method creates a new network when no results are found for existing networks containing
        the IP address.
        :return: None
        """
        first_count = self.count_networks()
        self.__call_get_ip_address_for_organization()
        second_count = self.count_networks()
        self.assertEqual(first_count + 1, second_count)

    def test_no_result_assigns_network(self):
        """
        Tests that the method correctly assigns the expected network as the parent of the returned IP address
        when no results are found.
        :return: None
        """
        address = self.__call_get_ip_address_for_organization()
        network = self.get_last_created_network()
        self.assertEqual(address.network, network)

    def test_no_result_creates_network_mask_length(self):
        """
        Tests that the method assigns the correct network mask length for the created network when
        no results are found.
        :return: None
        """
        self.__call_get_ip_address_for_organization(network_mask_length=24)
        network = self.get_last_created_network()
        self.assertEqual(network.mask_length, 24)

    def test_no_results_assign_organization(self):
        """
        Tests that the method assigns the correct organization as a parent of the newly-created network when
        no results are found.
        :return: None
        """
        organization = self.get_organization_for_user()
        self.__call_get_ip_address_for_organization(org_uuid=organization.uuid)
        network = self.get_last_created_network()
        self.assertEqual(network.organization, organization)

    def test_race_condition(self):
        """
        Tests that the method returns an IP address in the expected network range when an integrity error
        is thrown and the network is a class C.
        :return: None
        """
        original_func = lib.sqlalchemy.ops.networks.get_containing_network_uuid_for_organization

        network = self.create_network_for_user(user="user_1", address=WsTestData.UNUSED_IP_CLASS_C, mask_length=24)
        self.db_session.commit()
        self._mock_invoke_count = 0

        def get_containing_mock(*args, **kwargs):
            self._mock_invoke_count += 1
            if self._mock_invoke_count == 1:
                raise NoResultFoundError()
            else:
                return network.uuid

        lib.sqlalchemy.ops.networks.get_containing_network_uuid_for_organization = MagicMock(side_effect=get_containing_mock)
        ip_address = self.__call_get_ip_address_for_organization()
        lib.sqlalchemy.ops.networks.get_containing_network_uuid_for_organization = original_func
        self.assertEqual(ip_address.network, network)

    def test_returns_ip_address(self):
        """
        Tests that the method returns an instance of the expected class type.
        :return: None
        """
        address = self.__call_get_ip_address_for_organization()
        self.assertTrue(isinstance(address, IpAddress))

    def test_creates_ip_address(self):
        """
        Tests that the method creates an IP address when a matching address does not already exist.
        :return: None
        """
        first_count = self.count_ip_addresses()
        self.__call_get_ip_address_for_organization()
        second_count = self.count_ip_addresses()
        self.assertEqual(first_count + 1, second_count)

    def test_does_not_create_ip_address(self):
        """
        Tests that the method does not create an IP address when a matching address already exists.
        :return: None
        """
        self.__call_get_ip_address_for_organization()
        first_count = self.count_ip_addresses()
        self.__call_get_ip_address_for_organization()
        second_count = self.count_ip_addresses()
        self.assertEqual(first_count, second_count)
