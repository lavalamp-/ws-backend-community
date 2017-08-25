# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models
from tests.rest_tests.mixin import ListTestCaseMixin, PresentableTestCaseMixin, ExporterCustomFieldsMixin, \
    ExporterTestCaseMixin, RetrieveTestCaseMixin, CustomFieldsMixin, ParameterizedRouteMixin,\
    UpdateTestCaseMixin, CreateTestCaseMixin
from ..base import WsDjangoViewTestCase


class TestScanConfigListView(
    ListTestCaseMixin,
    PresentableTestCaseMixin,
    ExporterCustomFieldsMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for testing the ScanConfigListView APIView.
    """

    _api_route = "/scan-configs/"

    def __send_list_request(self, user="user_1", query_string=None, login=True):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user to send the request as.
        :param query_string: The query string to include in the URL.
        :param login: Whether or not to log the requesting user in.
        :return: The HTTP response.
                """
        if login:
            self.login(user=user)
        return self.get(query_string=query_string)

    @property
    def custom_fields_field(self):
        return "uuid"

    @property
    def custom_fields_method(self):
        return self.__send_list_request

    @property
    def list_method(self):
        return self.__send_list_request

    @property
    def presentation_method(self):
        return self.__send_list_request

    @property
    def response_has_many(self):
        return True


class TestScanConfigDetailView(
    UpdateTestCaseMixin,
    RetrieveTestCaseMixin,
    PresentableTestCaseMixin,
    CustomFieldsMixin,
    ParameterizedRouteMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for the ScanConfigDetailView APIView.
    """

    _api_route = "/scan-configs/%s/"
    _url_parameters = None

    def __send_retrieve_request(self, user="user_1", query_string=None, login=True, input_uuid="POPULATE"):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: The user to send the request as.
        :param query_string: The query string to include in the URL.
        :param login: Whether or not to log in before sending the request.
        :param input_uuid: The UUID of the order to retrieve.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            order = self.get_scan_config_for_user(user=user)
            input_uuid = str(order.uuid)
        self._url_parameters = input_uuid
        return self.get(query_string=query_string)

    def __send_update_request(
            self,
            user="user_1",
            login=True,
            query_string=None,
            input_uuid="POPULATE",
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
    ):
        """
        Send an update request to the remote endpoint to update the reference scan config.
        :param user: The user to submit the request as.
        :param login: Whether or not to log the user in prior to sending the request.
        :param query_string: The query string to submit alongside the URL.
        :param input_uuid: The UUID of the order that owns the scan config.
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
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            order = self.get_scan_config_for_user(user=user)
            input_uuid = str(order.uuid)
        self._url_parameters = input_uuid
        to_send = {}
        if include_name:
            to_send["name"] = name
        if include_description:
            to_send["description"] = description
        if include_is_default:
            to_send["is_default"] = is_default
        if include_saved_for_later:
            to_send["saved_for_later"] = saved_for_later
        if include_scan_domain_names:
            to_send["scan_domain_names"] = scan_domain_names
        if include_scan_network_ranges:
            to_send["scan_network_ranges"] = scan_network_ranges
        if include_scan_ip_addresses:
            to_send["scan_ip_addresses"] = scan_ip_addresses
        if include_scan_network_services:
            to_send["scan_network_services"] = scan_network_services
        if include_scan_ssl_support:
            to_send["scan_ssl_support"] = scan_ssl_support
        if include_dns_enumerate_subdomains:
            to_send["dns_enumerate_subdomains"] = dns_enumerate_subdomains
        if include_dns_scan_resolutions:
            to_send["dns_scan_resolutions"] = dns_scan_resolutions
        if include_network_scan_bandwidth:
            to_send["network_scan_bandwidth"] = network_scan_bandwidth
        if include_network_inspect_live_hosts:
            to_send["network_inspect_live_hosts"] = network_inspect_live_hosts
        if include_ip_address_geolocate:
            to_send["ip_address_geolocate"] = ip_address_geolocate
        if include_ip_address_reverse_hostname:
            to_send["ip_address_reverse_hostname"] = ip_address_reverse_hostname
        if include_ip_address_historic_dns:
            to_send["ip_address_historic_dns"] = ip_address_historic_dns
        if include_ip_address_as_data:
            to_send["ip_address_as_data"] = ip_address_as_data
        if include_ip_address_whois_data:
            to_send["ip_address_whois_data"] = ip_address_whois_data
        if include_network_service_check_liveness:
            to_send["network_service_check_liveness"] = network_service_check_liveness
        if include_network_service_fingerprint:
            to_send["network_service_fingerprint"] = network_service_fingerprint
        if include_network_service_inspect_app:
            to_send["network_service_inspect_app"] = network_service_inspect_app
        if include_ssl_enumerate_vulns:
            to_send["ssl_enumerate_vulns"] = ssl_enumerate_vulns
        if include_ssl_enumerate_cipher_suites:
            to_send["ssl_enumerate_cipher_suites"] = ssl_enumerate_cipher_suites
        if include_ssl_retrieve_cert:
            to_send["ssl_retrieve_cert"] = ssl_retrieve_cert
        if include_app_inspect_web_app:
            to_send["app_inspect_web_app"] = app_inspect_web_app
        if include_web_app_include_http_on_https:
            to_send["web_app_include_http_on_https"] = web_app_include_http_on_https
        if include_web_app_enum_vhosts:
            to_send["web_app_enum_vhosts"] = web_app_enum_vhosts
        if include_web_app_take_screenshot:
            to_send["web_app_take_screenshot"] = web_app_take_screenshot
        if include_web_app_do_crawling:
            to_send["web_app_do_crawling"] = web_app_do_crawling
        if include_web_app_enum_user_agents:
            to_send["web_app_enum_user_agents"] = web_app_enum_user_agents
        return self.patch(query_string=query_string, data=to_send)

    @property
    def custom_fields_field(self):
        return "uuid"

    @property
    def custom_fields_method(self):
        return self.__send_retrieve_request

    @property
    def presentation_method(self):
        return self.__send_retrieve_request

    @property
    def response_has_many(self):
        return False

    @property
    def retrieve_method(self):
        return self.__send_retrieve_request

    @property
    def retrieved_object_class(self):
        return rest.models.ScanConfig

    @property
    def update_method(self):
        return self.__send_update_request

    @property
    def updated_model_class(self):
        return rest.models.ScanConfig


class TestDnsRecordTypesByScanConfigView(
    ListTestCaseMixin,
    CreateTestCaseMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    ExporterCustomFieldsMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for the DnsRecordTypesByScanConfigView APIView.
    """

    _api_route = "/scan-configs/%s/dns-record-types/"
    _url_parameters = None

    def test_create_creates_object(self, *args, **kwargs):
        scan_config = self.get_scan_config_for_user()
        scan_config.dns_record_types.all().delete()
        super(TestDnsRecordTypesByScanConfigView, self).test_create_creates_object()

    def __send_create_request(
            self,
            user="user_1",
            query_string=None,
            input_uuid="POPULATE",
            login=True,
            include_record_type=True,
            record_type="A",
            delete_existing_record_type=True,
    ):
        """
        Send an HTTP request to the configured API endpoint to create a new child model object and return
        the response.
        :param user: The user to send the request on behalf of.
        :param query_string: The query string to include in the URL.
        :param input_uuid: The UUID of the parent object to query.
        :param login: Whether or not to log in before sending the request.
        :param include_record_type: Whether or not to include the record_type parameter.
        :param record_type: The record_type parameter to include.
        :param delete_existing_record_type: Whether or not to delete the existing record type that matches
        record_type for the referenced ScanConfig.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            scan_config = self.get_scan_config_for_user(user=user)
            input_uuid = str(scan_config.uuid)
        self._url_parameters = input_uuid
        to_send = {}
        if include_record_type:
            to_send["record_type"] = record_type
        if delete_existing_record_type:
            scan_config = rest.models.ScanConfig.objects.get(pk=input_uuid)
            try:
                scan_config.dns_record_types.get(record_type=record_type).delete()
            except rest.models.DnsRecordType.DoesNotExist:
                pass
        return self.post(query_string=query_string, data=to_send)

    def __send_list_request(self, user="user_1", query_string=None, input_uuid="POPULATE", login=True):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user to send the request as.
        :param query_string: The query string to include in the URL.
        :param login: Whether or not to log the requesting user in.
        :param input_uuid: The UUID of the ScanConfig object to request.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            scan_config = self.get_scan_config_for_user(user=user)
            input_uuid = str(scan_config.uuid)
        self._url_parameters = input_uuid
        return self.get(query_string=query_string)

    @property
    def create_method(self):
        return self.__send_create_request

    @property
    def created_object_class(self):
        return rest.models.DnsRecordType

    @property
    def custom_fields_field(self):
        return "uuid"

    @property
    def custom_fields_method(self):
        return self.__send_list_request

    @property
    def list_method(self):
        return self.__send_list_request

    @property
    def presentation_method(self):
        return self.__send_list_request

    @property
    def response_has_many(self):
        return True


class TestScanPortsByScanConfigView(
    ListTestCaseMixin,
    CreateTestCaseMixin,
    PresentableTestCaseMixin,
    ParameterizedRouteMixin,
    ExporterCustomFieldsMixin,
    ExporterTestCaseMixin,
    WsDjangoViewTestCase,
):
    """
    This is a test case for the ScanPortsByScanConfigView APIView.
    """

    _api_route = "/scan-configs/%s/scan-ports/"
    _url_parameters = None

    def __send_create_request(
            self,
            user="user_1",
            query_string=None,
            input_uuid="POPULATE",
            login=True,
            include_port_number=True,
            port_number=1234,
            include_protocol=True,
            protocol="TCP",
    ):
        """
        Send an HTTP request to the configured API endpoint to create a new child model object and return
        the response.
        :param user: The user to send the request on behalf of.
        :param query_string: The query string to include in the URL.
        :param input_uuid: The UUID of the parent object to query.
        :param login: Whether or not to log in before sending the request.
        :param include_port_number: Whether or not to include the port number in the request.
        :param port_number: The port number to include in the request.
        :param include_protocol: Whether or not to include the protocol in the request.
        :param protocol: The protocol to include in the request.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            scan_config = self.get_scan_config_for_user(user=user)
            input_uuid = str(scan_config.uuid)
        self._url_parameters = input_uuid
        to_send = {}
        if include_port_number:
            to_send["port_number"] = port_number
        if include_protocol:
            to_send["protocol"] = protocol
        return self.post(query_string=query_string, data=to_send)

    def __send_list_request(self, user="user_1", query_string=None, input_uuid="POPULATE", login=True):
        """
        Send an HTTP request to the configured API endpoint and return the response.
        :param user: A string depicting the user to send the request as.
        :param query_string: The query string to include in the URL.
        :param login: Whether or not to log the requesting user in.
        :param input_uuid: The UUID of the ScanConfig object to request.
        :return: The HTTP response.
        """
        if login:
            self.login(user=user)
        if input_uuid == "POPULATE":
            scan_config = self.get_scan_config_for_user(user=user)
            input_uuid = str(scan_config.uuid)
        self._url_parameters = input_uuid
        return self.get(query_string=query_string)

    @property
    def create_method(self):
        return self.__send_create_request

    @property
    def created_object_class(self):
        return rest.models.ScanPort

    @property
    def custom_fields_field(self):
        return "uuid"

    @property
    def custom_fields_method(self):
        return self.__send_list_request

    @property
    def list_method(self):
        return self.__send_list_request

    @property
    def presentation_method(self):
        return self.__send_list_request

    @property
    def response_has_many(self):
        return True
