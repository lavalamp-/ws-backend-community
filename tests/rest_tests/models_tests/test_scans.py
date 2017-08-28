# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebSightModelTestCase
import rest.models


class ScanConfigTestCase(BaseWebSightModelTestCase):
    """
    This is a test case for testing the ScanConfig model object.
    """

    def create_instance(self, user=None, organization=None, **kwargs):
        if user is None:
            user = self.get_user(user="user_1")
        if organization is None:
            organization = user.organizations[0]
        new_order = rest.models.Order.objects.create_from_user_and_organization(
            user=user,
            organization=organization,
        )
        return new_order.scan_config

    def test_create_populates_dns_record_types(self):
        """
        Tests that creating a ScanConfig object populates the DnsRecordType relation.
        :return: None
        """
        new_scan_config = self.create_instance()
        self.assertGreater(new_scan_config.dns_record_types.count(), 0)

    def test_create_populates_scan_ports(self):
        """
        Tests that creating a ScanConfig object populates the ScanPort relation.
        :return: None
        """
        new_scan_config = self.create_instance()
        self.assertGreater(new_scan_config.scan_ports.count(), 0)

    def test_no_scans_configured_errors(self):
        """
        Tests that a ScanConfig object that has no scanning activities enabled reports
        such in its ready errors.
        :return: None
        """
        new_scan_config = self.create_instance()
        new_scan_config.scan_domain_names = False
        new_scan_config.scan_network_ranges = False
        new_scan_config.scan_ip_addresses = False
        new_scan_config.scan_network_services = False
        new_scan_config.scan_ssl_support = False
        errors = new_scan_config.get_ready_errors()
        self.assertIn("No scanning activities", errors[0])

    def test_no_scan_ports_configured_error(self):
        """
        Tests that a ScanConfig object that has no scan ports enabled and has either
        version of network scanning enabled reports such in its ready errors.
        :return: None
        """
        new_scan_config = self.create_instance()
        new_scan_config.scan_network_ranges = True
        new_scan_config.scan_ports.all().delete()
        errors = new_scan_config.get_ready_errors()
        self.assertIn("Network port scanning is enabled", errors[0])

    def test_no_zmap_bandwidth_error(self):
        """
        Tests that a ScanConfig object that has no Zmap bandwidth specified reports such
        in its ready errors.
        :return: None
        """
        new_scan_config = self.create_instance()
        new_scan_config.scan_network_ranges = True
        new_scan_config.network_scan_bandwidth = "0M"
        errors = new_scan_config.get_ready_errors()
        self.assertIn("Network port scanning is enabled but the bandwidth", errors[0])

    def test_no_domain_names_error(self):
        """
        Tests that a ScanConfig object that has no domain names specified yet has DNS enumeration
        enabled reports such in its errors.
        :return: None
        """
        new_scan_config = self.create_instance()
        new_scan_config.scan_domain_names = True
        new_scan_config.dns_record_types.all().delete()
        errors = new_scan_config.get_ready_errors()
        self.assertIn("DNS scanning is enabled", errors[0])

    @property
    def model_class(self):
        return rest.models.ScanConfig
