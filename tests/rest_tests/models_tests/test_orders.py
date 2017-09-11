# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebSightModelTestCase
import rest.models


class OrderTestCase(BaseWebSightModelTestCase):
    """
    This is a test case for testing the Order model class.
    """

    def create_instance(self, user=None, organization=None, **kwargs):
        if user is None:
            user = self.get_user(user="user_1")
        if organization is None:
            organization = user.organizations[0]
        return rest.models.Order.objects.create_from_user_and_organization(user=user, organization=organization)

    def __get_default_user_and_org(self, user="user_1"):
        """
        Get a tuple containing (1) the default test user and (2) the default test organization
        to use for creating and testing new order objects.
        :param user: A string depicting the user to retrieve.
        :return: A tuple containing (1) the default test user and (2) the default test organization
        to use for creating and testing new order objects.
        """
        user_obj = self.get_user(user=user)
        organization = self.get_organization_for_user(user=user)
        return user_obj, organization

    def test_create_from_populates_networks(self):
        """
        Tests that creating an order from org/user populates the networks relation.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        self.assertGreater(new_order.networks.count(), 0)

    def test_create_from_populates_networks_count(self):
        """
        Tests that creating an order from org/user populates the expected number of networks.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        self.assertEqual(new_order.networks.count(), org.monitored_networks_count)

    def test_create_from_populates_domain_names(self):
        """
        Tests that creating an order from org/user populates the domain names relation.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        self.assertGreater(new_order.domain_names.count(), 0)

    def test_create_from_populates_domain_names_count(self):
        """
        Tests that creating an order from org/user populates the expected number of
        domain names.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        self.assertEqual(new_order.domain_names.count(), org.monitored_domains_count)

    def test_create_from_populates_user(self):
        """
        Tests that creating an order from org/user populates the expected user field.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        self.assertEqual(new_order.user, user)

    def test_create_from_populates_organization(self):
        """
        Tests that creating an order from org/user populates the expected organization
        field.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        self.assertEqual(new_order.organization, org)

    def test_create_populates_scan_config(self):
        """
        Tests that creating an order populates the scan_config attribute.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        self.assertIsNotNone(new_order.scan_config)

    def test_create_scan_config_order(self):
        """
        Tests that creating an order associates the order with the ScanConfig.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        self.assertEqual(new_order.scan_config.order, new_order)

    def test_create_scan_config_user(self):
        """
        Tests that creating an order associates the order with the proper user.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        self.assertEqual(new_order.scan_config.user, user)

    def test_no_scan_config_errors(self):
        """
        Tests that the order returns the expected error string when it has no ScanConfig
        associated with it.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        new_order.scan_config = None
        new_order.save()
        errors = new_order.get_ready_errors()
        self.assertIn("The order has no scanning", errors[0])

    def test_scan_config_errors(self):
        """
        Tests that the order returns a non-empty error list when it has a ScanConfig that
        has errors in it.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        new_order.scan_config.scan_network_ranges = True
        new_order.scan_config.network_scan_bandwidth = "0M"
        errors = new_order.get_ready_errors()
        self.assertGreater(len(errors), 0)

    def test_has_been_placed_errors(self):
        """
        Tests that the order returns the expected error string when it has already been placed.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        new_order.has_been_placed = True
        errors = new_order.get_ready_errors()
        self.assertIn("This order has already been", errors[0])

    def test_no_endpoints_defined_errors(self):
        """
        Tests that the order returns the expected error string when no endpoints have been defined
        in the order.
        :return: None
        """
        user, org = self.__get_default_user_and_org()
        new_order = self.create_instance(user=user, organization=org)
        new_order.networks.all().delete()
        new_order.domain_names.all().delete()
        errors = new_order.get_ready_errors()
        self.assertIn("No networks, IP addresses", errors[0])

    @property
    def model_class(self):
        return rest.models.Order
