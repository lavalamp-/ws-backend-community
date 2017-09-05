# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import models
import json

from lib import JsonSerializableMixin, ConfigManager
from .base import BaseWsModel
from .orders import Order
from .wsuser import WsUser
from lib import FileHelper, RegexLib

config = ConfigManager.instance()


class ScanInvocation(BaseWsModel):
    """
    This is a class for representing when a user has invoked a scan of a given organization.
    """

    # Columns

    # Foreign Keys

    organization = models.ForeignKey(
        "Organization",
        related_name="scan_invocations",
        null=True,
        on_delete=models.CASCADE,
    )


class ScanConfigManager(models.Manager):
    """
    This is a manager class for handling operations around the creation and manipulation of
    ScanConfig objects.
    """

    def create(self, include_default_dns_record_types=True, include_default_scan_ports=True, **kwargs):
        """
        Create the ScanConfig and all of the necessary related objects.
        :param include_default_dns_record_types: Whether or not to populate the default DNS record types in the
        created object.
        :param include_default_scan_ports: Whether or not to populate the default scan ports in the created
        object.
        :param kwargs: Keyword arguments to pass to the create method.
        :return: The newly-created ScanConfig object.
        """
        scan_config = super(ScanConfigManager, self).create(**kwargs)
        if include_default_dns_record_types:
            self.__create_default_dns_record_types_for_config(scan_config)
        if include_default_scan_ports:
            self.__create_default_scan_ports_for_config(scan_config)
        return scan_config

    def write_defaults_to_file(self):
        """
        Write the contents of all of the default ScanConfig objects to the ScanConfig JSON file.
        :return: None
        """
        configs = ScanConfig.objects.filter(is_default=True).all()
        to_write = [x.to_json() for x in configs]
        with open(config.files_default_scan_config_path, "w+") as f:
            f.write(json.dumps(to_write))

    def __create_default_dns_record_types_for_config(self, scan_config):
        """
        Get a list of DnsRecordType models representing the default record types to include
        in scans.
        :param scan_config: The ScanConfig to associate the DNS record types with.
        :return: A list of DnsRecordType models representing the default record types to include
        in scans.
        """
        from .dns import DnsRecordType
        dns_record_types = FileHelper.get_dns_record_types()
        to_return = []
        for record_type, include_by_default, scan in dns_record_types:
            if include_by_default:
                to_return.append(DnsRecordType.objects.create(
                    record_type=record_type,
                    scan_config=scan_config,
                ))
        return to_return

    def __create_default_scan_ports_for_config(self, scan_config):
        """
        Get a list of ScanPort objects representing the default ports to run network scans for
        in scans.
        :param scan_config: The ScanConfig to associate the DNS record types with.
        :return: A list of ScanPort objects representing the default ports to run network scans for
        in scans.
        """
        from .organizations import ScanPort
        scan_ports = FileHelper.get_scan_ports_and_protocols()
        to_return = []
        for port_number, protocol in scan_ports:
            to_return.append(ScanPort.objects.create(
                port_number=port_number,
                protocol=protocol,
                scan_config=scan_config,
            ))
        return to_return


class ScanConfig(BaseWsModel, JsonSerializableMixin):
    """
    This is a class for representing the configuration options associated with a single scan.
    """

    objects = ScanConfigManager()

    # Columns

    # Reference

    name = models.CharField(
        max_length=64,
        help_text="A name to associate with this scanning configuration.",
        null=True,
    )
    description = models.CharField(
        max_length=256,
        help_text="A brief description about what this scanning configuration entails.",
        null=True,
    )
    is_default = models.BooleanField(
        default=False,
        null=False,
        help_text="Whether or not this scanning configuration is one of the default configurations "
                  "provided by Web Sight.",
    )
    saved_for_later = models.BooleanField(
        default=False,
        null=False,
        help_text="Whether or not this scanning configuration should be saved as a configuration that "
                  "can be used in future scans.",
    )

    # General Setup

    scan_domain_names = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to scan domain names associated with the scan.",
    )
    scan_network_ranges = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to scan network ranges associated with the scan.",
    )
    scan_ip_addresses = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to gather information about individual IP addresses.",
    )
    scan_network_services = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to gather information about individual network services.",
    )
    scan_ssl_support = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to gather information about SSL supporting services.",
    )

    # DNS

    dns_enumerate_subdomains = models.BooleanField(
        default=False,
        null=False,
        help_text="Whether or not to enumerate subdomains.",
    )
    dns_scan_resolutions = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to scan IP addresses associated with domain name resolutions.",
    )

    # Networks

    network_scan_bandwidth = models.CharField(
        max_length=16,
        default="10M",
        null=False,
        help_text="The maximum bandwidth to throttle Zmap scans at.",
    )
    network_inspect_live_hosts = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to continue gathering host-specific information when a host is found "
                  "to be alive as a result of network discovery."
    )

    # IP Addresses

    ip_address_geolocate = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to geolocate IP addresses.",
    )
    ip_address_reverse_hostname = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to retrieve reverse hostname data for IP addresses.",
    )
    ip_address_historic_dns = models.BooleanField(
        default=False,
        null=False,
        help_text="Whether or not to retrieve historic DNS data for IP addresses.",
    )
    ip_address_as_data = models.BooleanField(
        default=False,
        null=False,
        help_text="Whether or not toint retrieve data about IP addresses' autonomous systems.",
    )
    ip_address_whois_data = models.BooleanField(
        default=False,
        null=False,
        help_text="Whether or not to retrieve WHOIS data about an IP address.",
    )

    # Network Services

    network_service_check_liveness = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to check for network service liveness.",
    )
    network_service_fingerprint = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to fingerprint the applications found on live network services.",
    )
    network_service_inspect_app = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to inspect applications found on live network services.",
    )

    # SSL

    ssl_enumerate_vulns = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to enumerate the presence of vulnerabilities in SSL services.",
    )
    ssl_enumerate_cipher_suites = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to enumerate the supported cipher suites found within an SSL service.",
    )
    ssl_retrieve_cert = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to retrieve the certificate presented by an SSL supporting service.",
    )

    # Applications

    app_inspect_web_app = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to inspect discovered web applications.",
    )

    # Web Apps

    web_app_include_http_on_https = models.BooleanField(
        default=False,
        null=False,
        help_text="Whether or not to inspect HTTP services that are hosted on the same IP address "
                  "and port as HTTPS services.",
    )
    web_app_enum_vhosts = models.BooleanField(
        default=False,
        null=False,
        help_text="Whether or not to enumerate virtual hosts for web servers.",
    )
    web_app_take_screenshot = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to take screenshots of web applications.",
    )
    web_app_do_crawling = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to crawl web applications or just retrieve the landing page resource.",
    )
    web_app_enum_user_agents = models.BooleanField(
        default=True,
        null=False,
        help_text="Whether or not to gather information about user agent responses for a web application.",
    )

    # Foreign Keys

    order = models.OneToOneField(
        Order,
        on_delete=models.CASCADE,
        null=True,
        related_name="scan_config",
    )

    organization = models.ForeignKey(
        "rest.Organization",
        related_name="scan_configs",
        on_delete=models.CASCADE,
        null=True,
    )

    user = models.ForeignKey(
        WsUser,
        related_name="scan_configs",
        on_delete=models.CASCADE,
        null=True,
    )

    @staticmethod
    def from_json(to_parse):
        from .organizations import ScanPort
        from .dns import DnsRecordType
        to_return = ScanConfig.objects.create(
            include_default_dns_record_types=False,
            include_default_scan_ports=False,
            name=to_parse["name"],
            description=to_parse["description"],
            is_default=to_parse["is_default"],
            saved_for_later=to_parse["saved_for_later"],
            scan_domain_names=to_parse["scan_domain_names"],
            scan_network_ranges=to_parse["scan_network_ranges"],
            scan_ip_addresses=to_parse["scan_ip_addresses"],
            scan_network_services=to_parse["scan_network_services"],
            scan_ssl_support=to_parse["scan_ssl_support"],
            dns_enumerate_subdomains=to_parse["dns_enumerate_subdomains"],
            dns_scan_resolutions=to_parse["dns_scan_resolutions"],
            network_scan_bandwidth=to_parse["network_scan_bandwidth"],
            network_inspect_live_hosts=to_parse["network_inspect_live_hosts"],
            ip_address_geolocate=to_parse["ip_address_geolocate"],
            ip_address_reverse_hostname=to_parse["ip_address_reverse_hostname"],
            ip_address_as_data=to_parse["ip_address_as_data"],
            ip_address_whois_data=to_parse["ip_address_whois_data"],
            network_service_check_liveness=to_parse["network_service_check_liveness"],
            network_service_fingerprint=to_parse["network_service_fingerprint"],
            network_service_inspect_app=to_parse["network_service_inspect_app"],
            ssl_enumerate_vulns=to_parse["ssl_enumerate_vulns"],
            ssl_enumerate_cipher_suites=to_parse["ssl_enumerate_cipher_suites"],
            ssl_retrieve_cert=to_parse["ssl_retrieve_cert"],
            app_inspect_web_app=to_parse["app_inspect_web_app"],
            web_app_include_http_on_https=to_parse["web_app_include_http_on_https"],
            web_app_enum_vhosts=to_parse["web_app_enum_vhosts"],
            web_app_take_screenshot=to_parse["web_app_take_screenshot"],
            web_app_do_crawling=to_parse["web_app_do_crawling"],
            web_app_enum_user_agents=to_parse["web_app_enum_user_agents"],
        )
        scan_ports = []
        for scan_port_json in to_parse["scan_ports"]:
            scan_port_json["scan_config"] = to_return
            scan_ports.append(ScanPort.from_json(scan_port_json))
        to_return.scan_ports = scan_ports
        dns_record_types = []
        for dns_record_type_json in to_parse["dns_record_types"]:
            dns_record_type_json["scan_config"] = to_return
            dns_record_types.append(DnsRecordType.from_json(dns_record_type_json))
        to_return.dns_record_types = dns_record_types
        return to_return

    def get_ready_errors(self):
        """
        Get a list of strings describing errors associated with this ScanConfig object that prevent it
        from being used in a placed order.
        :return: A list of strings describing errors associated with this ScanConfig object that prevent it
        from being used in a placed order.
        """
        to_return = []
        if not self.scan_domain_names \
                and not self.scan_network_ranges \
                and not self.scan_ip_addresses \
                and not self.scan_network_services \
                and not self.scan_ssl_support:
            to_return.append("No scanning activities are enabled.")
        if self.scan_network_ranges or self.scan_ip_addresses:
            if self.scan_ports.count() == 0:
                to_return.append("Network port scanning is enabled but no ports are defined.")
        if self.scan_network_ranges and RegexLib.zmap_empty_bandwidth_regex.match(self.network_scan_bandwidth):
            to_return.append(
                "Network port scanning is enabled but the bandwidth is set to zero (%s)."
                % (self.network_scan_bandwidth,)
            )
        if self.scan_domain_names:
            if self.dns_record_types.count() == 0:
                to_return.append("DNS scanning is enabled but no record types are defined.")
        return to_return

    def to_json(self):
        """
        Get a JSON dictionary representing the internal state of this object.
        :return: A JSON dictionary representing the internal state of this object.
        """
        return {
            "name": self.name,
            "description": self.description,
            "is_default": self.is_default,
            "saved_for_later": self.saved_for_later,
            "scan_domain_names": self.scan_domain_names,
            "scan_network_ranges": self.scan_network_ranges,
            "scan_ip_addresses": self.scan_ip_addresses,
            "scan_network_services": self.scan_network_services,
            "scan_ssl_support": self.scan_ssl_support,
            "dns_enumerate_subdomains": self.dns_enumerate_subdomains,
            "dns_scan_resolutions": self.dns_scan_resolutions,
            "network_scan_bandwidth": self.network_scan_bandwidth,
            "network_inspect_live_hosts": self.network_inspect_live_hosts,
            "ip_address_geolocate": self.ip_address_geolocate,
            "ip_address_reverse_hostname": self.ip_address_reverse_hostname,
            "ip_address_as_data": self.ip_address_as_data,
            "ip_address_whois_data": self.ip_address_whois_data,
            "network_service_check_liveness": self.network_service_check_liveness,
            "network_service_fingerprint": self.network_service_fingerprint,
            "network_service_inspect_app": self.network_service_inspect_app,
            "ssl_enumerate_vulns": self.ssl_enumerate_vulns,
            "ssl_enumerate_cipher_suites": self.ssl_enumerate_cipher_suites,
            "ssl_retrieve_cert": self.ssl_retrieve_cert,
            "app_inspect_web_app": self.app_inspect_web_app,
            "web_app_include_http_on_https": self.web_app_include_http_on_https,
            "web_app_enum_vhosts": self.web_app_enum_vhosts,
            "web_app_take_screenshot": self.web_app_take_screenshot,
            "web_app_do_crawling": self.web_app_do_crawling,
            "web_app_enum_user_agents": self.web_app_enum_user_agents,
            "scan_ports": [x.to_json() for x in self.scan_ports.all()],
            "dns_record_types": [x.to_json() for x in self.dns_record_types.all()],
        }

    @property
    def can_be_modified(self):
        """
        Get whether or not this ScanConfig object can be modified.
        :return: whether or not this ScanConfig object can be modified.
        """
        if self.order:
            return not self.order.has_been_placed
        else:
            return True

    @property
    def is_ready_to_place(self):
        """
        Get a boolean depicting whether or not this scan config is ready to be a part of
        a placed order.
        :return: A boolean depicting whether or not this scan config is ready to be a part of
        a placed order.
        """
        return len(self.get_ready_errors()) == 0

    def __repr__(self):
        return "<%s - %s (%s, %s)>" % (
            self.__class__.__name__,
            self.uuid,
            self.name,
            self.is_default,
        )
