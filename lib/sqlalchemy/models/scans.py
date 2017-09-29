# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import from_django_model
from .dns import DnsRecordType
from .organizations import ScanPort
import rest.models

ScanConfig = from_django_model(rest.models.ScanConfig)


def duplicate(self):
    """
    Duplicate the contents of the referenced ScanConfig and return it.
    :return: A tuple containing (1) the newly-created ScanConfig and (2) a list
    containing all of the newly-created database model objects.
    """
    dns_record_types = []
    scan_ports = []
    scan_config = ScanConfig.new(
        name=self.name,
        description=self.description,
        is_default=False,
        saved_for_later=False,
        scan_domain_names=self.scan_domain_names,
        scan_network_ranges=self.scan_network_ranges,
        scan_ip_addresses=self.scan_ip_addresses,
        scan_network_services=self.scan_network_services,
        scan_ssl_support=self.scan_ssl_support,
        dns_enumerate_subdomains=self.dns_enumerate_subdomains,
        dns_scan_resolutions=self.dns_scan_resolutions,
        network_scan_bandwidth=self.network_scan_bandwidth,
        network_inspect_live_hosts=self.network_inspect_live_hosts,
        ip_address_geolocate=self.ip_address_geolocate,
        ip_address_reverse_hostname=self.ip_address_reverse_hostname,
        ip_address_historic_dns=self.ip_address_historic_dns,
        ip_address_as_data=self.ip_address_as_data,
        ip_address_whois_data=self.ip_address_whois_data,
        network_service_check_liveness=self.network_service_check_liveness,
        network_service_fingerprint=self.network_service_fingerprint,
        network_service_inspect_app=self.network_service_inspect_app,
        ssl_enumerate_vulns=self.ssl_enumerate_vulns,
        ssl_enumerate_cipher_suites=self.ssl_enumerate_cipher_suites,
        ssl_retrieve_cert=self.ssl_retrieve_cert,
        app_inspect_web_app=self.app_inspect_web_app,
        web_app_include_http_on_https=self.web_app_include_http_on_https,
        web_app_enum_vhosts=self.web_app_enum_vhosts,
        web_app_take_screenshot=self.web_app_take_screenshot,
        web_app_do_crawling=self.web_app_do_crawling,
        web_app_enum_user_agents=self.web_app_enum_user_agents,
        completion_web_hook_url=self.completion_web_hook_url,
        completion_email_org_users=False,
        completion_email_order_user=False,
    )
    for dns_record_type in self.dns_record_types:
        dns_record_types.append(DnsRecordType.new(
            record_type=dns_record_type.record_type,
            scan_config_id=scan_config.uuid,
        ))
    for scan_port in self.scan_ports:
        scan_ports.append(ScanPort.new(
            port_number=scan_port.port_number,
            protocol=scan_port.protocol,
            added_by=scan_port.added_by,
            included=scan_port.included,
            scan_config_id=scan_config.uuid,
        ))
    return scan_config, dns_record_types + scan_ports + [scan_config]

ScanConfig.duplicate = duplicate
