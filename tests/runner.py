# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json
from django.test.runner import DiscoverRunner
from django.utils import timezone
import time
from netaddr import IPNetwork
from lib import ConfigManager

from lib import WsFaker, RandomHelper, FilesystemHelper, WsIntrospectionHelper, bootstrap_all_database_models
from wselasticsearch.helper import ElasticsearchHelper
from .data import WsTestData
from rest.models import WsUser, Organization, Order
from wselasticsearch import bootstrap_index_model_mappings
from wselasticsearch.query import BulkElasticsearchQuery
from wselasticsearch.models import SslSupportReportModel, WebServiceReportModel, HttpTransactionModel, \
    DomainNameReportModel, HttpScreenshotModel, IpAddressReportModel
import rest.models

config = ConfigManager.instance()


class WebSightDiscoverRunner(DiscoverRunner):
    """
    This is a custom discover runner used by Web Sight to set up and tear down the test environment.
    """

    # Class Members

    _bulk_query = None
    _relationships_map = {}

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def run_suite(self, suite, **kwargs):
        """
        Override run_suite to handle setting up and tearing down Elasticsearch around the test
        suite.
        :param suite: The suite to run.
        :param kwargs: Keyword arguments.
        :return: The test suite result.
        """
        self.setup_web_sight_environment()
        result = super(WebSightDiscoverRunner, self).run_suite(suite, **kwargs)
        self.teardown_web_sight_environment()
        return result

    def setup_web_sight_environment(self):
        """
        Set up all of the necessary data in the Web Sight environment for tests.
        :return: None
        """
        print("Now populating database and Elasticsearch...")
        self.__populate_data()
        print("Performining bulk update on Elasticsearch...")
        self.bulk_query.save()
        print("Bulk query completed. Sleeping for 1 second to allow Elasticsearch time for indexing.")
        time.sleep(1)
        print("Test environment populated successfully.")

    def teardown_web_sight_environment(self):
        """
        Tear down all of the necessary data in the Web Sight environment that was used for the
        test suite.
        :return: None
        """
        print("Now tearing test environment down...")
        helper = ElasticsearchHelper.instance()
        orgs = Organization.objects.all()
        for org in orgs:
            helper.delete_index(org.uuid)
        print("Web Sight test environment torn down successfully.")

    # Protected Methods

    # Private Methods

    def __add_domain_name_report_to_domain_name_scan(
            self,
            domain_name_scan=None,
            user_string=None,
            is_latest_scan=False,
    ):
        """
        Add a domain name report to the given domain name scan.
        :param domain_name_scan: The domain name scan to add the report to.
        :param user_string: A string depicting the user that is being populated.
        :param is_latest_scan: Whether or not the report should be marked as a part of the
        latest domain name scan.
        :return: None
        """
        dummy_report = DomainNameReportModel.create_dummy()
        dummy_report = DomainNameReportModel.from_database_model(domain_name_scan, to_populate=dummy_report)
        dummy_report.is_latest_scan = is_latest_scan
        self.bulk_query.add_model_for_indexing(
            model=dummy_report,
            index=domain_name_scan.domain_name.organization.uuid,
        )

    def __add_http_screenshots_to_web_service_scan(
            self,
            web_service_scan=None,
            user_string=None,
            is_latest_scan=False,
            count=10,
    ):
        """
        Add HTTP screenshot Elasticsearch documents to the given web service scan.
        :param web_service_scan: The web service scan to add HTTP screenshots to.
        :param user_string: A string depicting the user that is being populated.
        :param is_latest_scan: Whether or not the HTTP screenshots should be marked as being a part
        of the latest web service scan.
        :param count: The number of HTTP screenshots to add to the web service scan.
        :return: None
        """
        models = []
        for i in range(count):
            dummy_model = HttpScreenshotModel.create_dummy()
            dummy_model = HttpScreenshotModel.from_database_model(web_service_scan, to_populate=dummy_model)
            dummy_model.is_latest_scan = is_latest_scan
            models.append(dummy_model)
        self.bulk_query.add_models_for_indexing(
            models=models,
            index=web_service_scan.web_service.network_service.ip_address.network.organization.uuid,
        )

    def __add_http_transactions_to_web_service_scan(
            self,
            web_service_scan=None,
            user_string=None,
            is_latest_scan=False,
            count=10,
    ):
        """
        Add HTTP transaction Elasticsearch documents to the given web service scan.
        :param web_service_scan: The web service scan to add HTTP transactions to.
        :param user_string: A string depicting the user that is being populated.
        :param is_latest_scan: Whether or not the HTTP transactions should be marked as being a part
        of the latest web service scan.
        :param count: The number of HTTP transactions to add to the web service scan.
        :return: None
        """
        models = []
        for i in range(count):
            dummy_model = HttpTransactionModel.create_dummy()
            dummy_model = HttpTransactionModel.from_database_model(web_service_scan, to_populate=dummy_model)
            dummy_model.is_latest_scan = is_latest_scan
            models.append(dummy_model)
        self.bulk_query.add_models_for_indexing(
            models=models,
            index=web_service_scan.web_service.network_service.ip_address.network.organization.uuid,
        )

    def __add_ip_address_report_to_ip_address_scan(self, ip_address_scan=None, user_string=None, is_latest_scan=False):
        """
        Add IP address report Elasticsearch documents to the given IP address scan.
        :param ip_address_scan: The IP address scan to add Elasticsearch documents to.
        :param user_string: A string depicting the user that is being populated.
        :param is_latest_scan: Whether or not the IP address report should be marked as the latest IP address
        report for the IP address.
        :return: None
        """
        dummy_report = IpAddressReportModel.create_dummy()
        dummy_report = IpAddressReportModel.from_database_model(ip_address_scan, to_populate=dummy_report)
        dummy_report.is_latest_scan = is_latest_scan
        if user_string not in self._relationships_map:
            self._relationships_map[user_string] = {}
        if "ip_address_report" not in self._relationships_map[user_string]:
            self._relationships_map[user_string]["ip-address-report"] = {}
        ip_address_uuid = str(ip_address_scan.ip_address.uuid)
        if ip_address_uuid not in self._relationships_map[user_string]["ip-address-report"]:
            self._relationships_map[user_string]["ip-address-report"][ip_address_uuid] = {
                "latest_scan": None,
                "not_latest_scan": [],
            }
        if is_latest_scan:
            self._relationships_map[user_string]["ip-address-report"][ip_address_uuid]["latest_scan"] = dummy_report
        else:
            self._relationships_map[user_string]["ip-address-report"][ip_address_uuid]["not_latest_scan"]\
                .append(dummy_report)
        self.bulk_query.add_model_for_indexing(
            model=dummy_report,
            index=ip_address_scan.ip_address.network.organization.uuid,
        )

    def __add_ssl_support_report_to_network_service_scan(
            self,
            network_service_scan=None,
            user_string=None,
            is_latest_scan=False,
    ):
        """
        Add SSL support report Elasticsearch documents to the given network service scan.
        :param network_service_scan: The network service scan to add Elasticsearch documents to.
        :param user_string: A string depicting the user that is being populated.
        :param is_latest_scan: Whether or not the SSL support report should be marked as the latest SSL
        support scan for the network service.
        :return: None
        """
        dummy_report = SslSupportReportModel.create_dummy()
        dummy_report = SslSupportReportModel.from_database_model(network_service_scan, to_populate=dummy_report)
        dummy_report.is_latest_scan = is_latest_scan
        if user_string not in self._relationships_map:
            self._relationships_map[user_string] = {}
        if "ssl-support-report" not in self._relationships_map[user_string]:
            self._relationships_map[user_string]["ssl-support-report"] = {}
        network_service_uuid = str(network_service_scan.network_service.uuid)
        if network_service_uuid not in self._relationships_map[user_string]["ssl-support-report"]:
            self._relationships_map[user_string]["ssl-support-report"][network_service_uuid] = {
                "latest_scan": None,
                "not_latest_scan": [],
            }
        if is_latest_scan:
            self._relationships_map[user_string]["ssl-support-report"][network_service_uuid]["latest_scan"] = dummy_report
        else:
            self._relationships_map[user_string]["ssl-support-report"][network_service_uuid]["not_latest_scan"].append(dummy_report)
        self.bulk_query.add_model_for_indexing(
            model=dummy_report,
            index=network_service_scan.network_service.ip_address.network.organization.uuid,
        )

    def __add_web_resources_to_web_service_scan(
            self,
            web_service_scan=None,
            user_string=None,
            is_latest_scan=None,
            count=2,
    ):
        """
        Add web service resource objects to the given web service scan.
        :param web_service_scan: The web service scan to add Elasticsearch documents to.
        :param user_string: A string depicting the user that is being populated.
        :param is_latest_scan: Whether or not the web resources should be marked as the latest web service
        report scan for the web service.
        :param count: The number of instances of each resource class to add.
        :return: None
        """
        resource_classes = [x[1] for x in WsIntrospectionHelper.get_web_resource_model_classes()]
        for resource_class in resource_classes:
            for i in range(count):
                dummy_resource = resource_class.create_dummy()
                dummy_resource = resource_class.from_database_model(web_service_scan, to_populate=dummy_resource)
                dummy_resource.is_latest_scan = is_latest_scan
                self.bulk_query.add_model_for_indexing(
                    model=dummy_resource,
                    index=web_service_scan.web_service.network_service.ip_address.network.organization.uuid,
                )

    def __add_web_service_report_to_web_service_scan(
            self,
            web_service_scan=None,
            user_string=None,
            is_latest_scan=False,
    ):
        """
        Add web service report Elasticsearch documents to the given web service scan.
        :param web_service_scan: The web service scan to add Elasticsearch documents to.
        :param user_string: A string depicting the user that is being populated.
        :param is_latest_scan: Whether or not the web service report should be marked as the latest web service
        report scan for the web service.
        :return: None
        """
        dummy_report = WebServiceReportModel.create_dummy()
        dummy_report = WebServiceReportModel.from_database_model(web_service_scan, to_populate=dummy_report)
        dummy_report.is_latest_scan = is_latest_scan
        network_service_uuid = str(web_service_scan.web_service.network_service.uuid)
        if is_latest_scan:
            ssl_report_model = self._relationships_map[user_string]["ssl-support-report"][network_service_uuid]["latest_scan"]
        else:
            ssl_report_model = self._relationships_map[user_string]["ssl-support-report"][network_service_uuid]["not_latest_scan"][0]
        dummy_report.populate_from_ssl_support(ssl_report_model)
        web_service_uuid = str(web_service_scan.web_service.uuid)
        if "web-service-report" not in self._relationships_map[user_string]:
            self._relationships_map[user_string]["web-service-report"] = {}
        if web_service_uuid not in self._relationships_map[user_string]["web-service-report"]:
            self._relationships_map[user_string]["web-service-report"][web_service_uuid] = {
                "latest_scan": None,
                "not_latest_scan": [],
            }
        if is_latest_scan:
            self._relationships_map[user_string]["web-service-report"][web_service_uuid]["latest_scan"] = dummy_report
        else:
            self._relationships_map[user_string]["web-service-report"][web_service_uuid]["not_latest_scan"].append(dummy_report)
        self.bulk_query.add_model_for_indexing(
            model=dummy_report,
            index=web_service_scan.web_service.network_service.ip_address.network.organization.uuid,
        )

    def __populate_data(self):
        """
        Populate the database with all of the necessary objects used for unit testing.
        :return: None
        """
        for user_string, user_kwargs in WsTestData.USERS.iteritems():
            self.__populate_user(user_string=user_string, user_kwargs=user_kwargs)
        bootstrap_all_database_models()

    def __populate_domain_name_scans_for_domain_name(self, domain_name=None, user_string=None, count=2):
        """
        Populate domain name scan objects for the given domain name.
        :param domain_name: The domain name to populate domain name scans for.
        :param user_string: A string depicting the user to add domain name scans for.
        :param count: The number of domain name scans to add to the domain name.
        :return: A list containing the domain name scans that were created by this method.
        """
        to_return = []
        for i in range(count):
            start_time = timezone.now() - WsFaker.get_timedelta()
            new_scan = domain_name.domain_name_scans.create(
                started_at=start_time,
            )
            self.__populate_elasticsearch_for_domain_name_scan(
                domain_name_scan=new_scan,
                is_latest_scan=i == count - 1,
                user_string=user_string,
            )
            to_return.append(new_scan)
        return to_return

    def __populate_domain_names_for_organization(self, organization=None, user_string=None, count=3):
        """
        Populate domain names for the given organization.
        :param organization: The organization to add domain names to.
        :param user_string: A string depicting the user to add domain names for.
        :param count: The number of domain names to add.
        :return: The newly-created domain names.
        """
        domains = set()
        while True:
            domains.add(WsFaker.get_domain_name())
            if len(domains) == count:
                break
        new_domains = []
        for domain in domains:
            new_domain = organization.domain_names.create(
                name=domain,
            )
            self.__populate_domain_name_scans_for_domain_name(domain_name=new_domain, user_string=user_string)
            new_domains.append(new_domain)
        return new_domains

    def __populate_elasticsearch_for_domain_name_scan(
            self,
            domain_name_scan=None,
            is_latest_scan=None,
            user_string=None,
    ):
        """
        Populate Elasticsearch data for the given domain name scan.
        :param domain_name_scan: The domain name scan to add data to Elasticsearch for.
        :param is_latest_scan: Whether or not the domain name scan is the latest domain
        name scan for its related domain name.
        :param user_string: A string depicting the user that is being populated.
        :return: None
        """
        self.__add_domain_name_report_to_domain_name_scan(
            domain_name_scan=domain_name_scan,
            user_string=user_string,
            is_latest_scan=is_latest_scan,
        )

    def __populate_elasticsearch_for_network_service_scan(
            self,
            network_service_scan=None,
            user_string=None,
            is_latest_scan=False,
    ):
        """
        Populate Elasticsearch data for the given network service scan.
        :param network_service_scan: The network service scan to populate data for.
        :param user_string: A string depicting the user that is being populated.
        :param is_latest_scan: Whether or not the data should be marked as coming from the latest network service
        scan.
        :return: None
        """
        self.__add_ssl_support_report_to_network_service_scan(
            network_service_scan=network_service_scan,
            user_string=user_string,
            is_latest_scan=is_latest_scan,
        )

    def __populate_elasticsearch_for_web_service_scan(
            self,
            web_service_scan=None,
            user_string=None,
            is_latest_scan=False
    ):
        """
        Populate Elasticsearch data for the given web service scan.
        :param web_service_scan: The web service scan to populate Elasticsearch data for.
        :param user_string: A string depicting the user that is being populated.
        :param is_latest_scan: Whether or not the data should be marked as coming from the latest web service
        scan.
        :return: None
        """
        self.__add_web_service_report_to_web_service_scan(
            web_service_scan=web_service_scan,
            user_string=user_string,
            is_latest_scan=is_latest_scan,
        )
        self.__add_http_transactions_to_web_service_scan(
            web_service_scan=web_service_scan,
            user_string=user_string,
            is_latest_scan=is_latest_scan,
        )
        self.__add_web_resources_to_web_service_scan(
            web_service_scan=web_service_scan,
            user_string=user_string,
            is_latest_scan=is_latest_scan,
        )
        self.__add_http_screenshots_to_web_service_scan(
            web_service_scan=web_service_scan,
            user_string=user_string,
            is_latest_scan=is_latest_scan,
        )

    def __populate_ip_addresses_for_network(self, network=None, user_string=None, count=2):
        """
        Populate the given network with IP addresses.
        :param network: The network to add IP addresses to.
        :param count: The number of IP addresses to add to the network.
        :param user_string: A string representing the user that is being populated.
        :return: The newly-created IP addresses.
        """
        network_range = IPNetwork(network.cidr_range)
        ip_address_strings = [str(x) for x in list(network_range[0:count])]
        ip_addresses = []
        for ip_address_string in ip_address_strings:
            new_ip_address = network.ip_addresses.create(
                address=ip_address_string,
                address_type="ipv4",
                is_monitored=False,
            )
            self.__populate_ip_address_scans_for_ip_address(
                ip_address=new_ip_address,
                user_string=user_string,
            )
            self.__populate_network_services_for_ip_address(ip_address=new_ip_address, user_string=user_string)
            ip_addresses.append(new_ip_address)
        return ip_addresses

    def __populate_ip_address_scans_for_ip_address(self, ip_address=None, user_string=None, count=2):
        """
        Populate the IP address scans for the given IP address.
        :param ip_address: The IP address to populate scans for.
        :param user_string: A string depicting the user to add the scans for.
        :param count: The number of IP address scans to add.
        :return: The newly-populated IP address scans.
        """
        new_scans = []
        for i in range(count):
            start_time = timezone.now() - WsFaker.get_timedelta()
            new_scan = ip_address.ip_address_scans.create(
                started_at=start_time,
            )
            self.__add_ip_address_report_to_ip_address_scan(
                ip_address_scan=new_scan,
                is_latest_scan=i == count - 1,
                user_string=user_string,
            )
            new_scans.append(new_scan)
        return new_scans

    def __populate_networks_for_organization(self, organization=None, user_string=None, count=2):
        """
        Populate the given organization with networks.
        :param organization: The organization to add networks to.
        :param user_string: A string representing the user that is being populated.
        :param count: The number of networks to add to the organization.
        :return: The newly-created networks.
        """
        network_ips = set()
        while True:
            network_ips.add(WsFaker.get_ipv4_address())
            if len(network_ips) == count:
                break
        new_networks = []
        for index, network_ip in enumerate(network_ips):
            new_network = organization.networks.create(
                address=network_ip,
                mask_length=24,
                name="Test Network %s" % (index,),
                scanning_enabled=True,
            )
            self.__populate_ip_addresses_for_network(network=new_network, user_string=user_string)
            new_networks.append(new_network)
        return new_networks

    def __populate_network_services_for_ip_address(self, ip_address=None, user_string=None, count=1):
        """
        Populate the given IP address with network services.
        :param ip_address: The IP address to add network services to.
        :param count: The number of network services to add to the IP address for each of the
        supported network service protocols (TCP, UDP).
        :param user_string: A string representing the user that is being populated.
        :return: The newly-created network services.
        """
        service_ports = set()
        while True:
            service_ports.add(WsFaker.get_random_int(minimum=1, maximum=65535))
            if len(service_ports) == count:
                break
        new_services = []
        for service_port in service_ports:
            new_tcp_service = ip_address.network_services.create(
                port=service_port,
                is_monitored=False,
                protocol="tcp",
                scanning_status=False,
                discovered_by=WsFaker.get_network_service_discovery_method(),
            )
            self.__populate_network_service_scans_for_network_service(
                network_service=new_tcp_service,
                user_string=user_string,
            )
            self.__populate_web_services_for_network_service(
                network_service=new_tcp_service,
                user_string=user_string,
            )
            new_services.append(new_tcp_service)
        return new_services

    def __populate_network_service_scans_for_network_service(self, network_service=None, user_string=None, count=2):
        """
        Populate network service scans for the given network service.
        :param network_service: The network service to add network service scans to.
        :param user_string: A string depicting the user that is being populated.
        :param count: The number of network service scans to add to the network service.
        :return: The newly-populated network service scans.
        """
        new_scans = []
        for i in range(count):
            start_time = timezone.now() - WsFaker.get_timedelta()
            new_scan = network_service.network_service_scans.create(
                started_at=start_time,
            )
            self.__populate_elasticsearch_for_network_service_scan(
                network_service_scan=new_scan,
                is_latest_scan=i == count - 1,
                user_string=user_string,
            )
            new_scans.append(new_scan)
        return new_scans

    def __populate_orders_for_organization(self, organization=None, user=None, user_string=None, count=3):
        """
        Create orders for the given user and return them.
        :param organization: The organization to create orders for.
        :param user: The user to populate orders for.
        :param user_string: A string depicting the user that orders are being created for.
        :param count: The number of orders to create.
        :return: The newly-created orders.
        """
        new_orders = []
        for i in range(count):
            new_order = Order.objects.create_from_user_and_organization(
                organization=organization,
                user=user,
            )
            new_orders.append(new_order)
        return new_orders

    def __populate_organization_for_user(self, user=None, user_string=None):
        """
        Create a testing organization for the given user, associated with the user, and return it.
        :param user: The user to add the organization to.
        :param user_string: A string representing the user that is being populated.
        :return: The newly-created organization.
        """
        org = Organization.objects.create(
            name="%s's Organization" % (user.first_name,),
            description="This is a description for %s's great organization." % (user.first_name,)
        )
        org.add_admin_user(user)
        bootstrap_index_model_mappings(index=org.uuid, delete_first=True)
        self.__populate_networks_for_organization(organization=org, user_string=user_string)
        self.__populate_domain_names_for_organization(organization=org, user_string=user_string)
        self.__populate_orders_for_organization(organization=org, user=user, user_string=user_string)
        return org

    def __populate_user(self, user_string=None, user_kwargs=None):
        """
        Create a user using the given key-word arguments and populate the user with all of the necessary
        objects for testing.
        :param user_string: A string representing the user that is being populated.
        :param user_kwargs: Keyword arguments to pass to the WsUser creation method.
        :return: The user that was created.
        """
        new_user = WsUser.objects.create_user(**user_kwargs)
        self.__populate_organization_for_user(user=new_user, user_string=user_string)
        return new_user

    def __populate_web_services_for_network_service(self, network_service=None, user_string=None, count=1):
        """
        Populate web services for the given network service.
        :param network_service: The network service to populate web services for.
        :param count: The number of web services to add to the network service.
        :param user_string: A string depicting the user that is being populated.
        :return: The list of newly-created web services.
        """
        hostnames = set()
        while True:
            hostnames.add(WsFaker.get_domain_name())
            if len(hostnames) == count:
                break
        new_services = []
        for hostname in hostnames:
            new_web_service = network_service.web_services.create(
                ip_address=network_service.ip_address.address,
                port=network_service.port,
                host_name=hostname,
                ssl_enabled=RandomHelper.flip_coin(),
            )
            self.__populate_web_service_scans_for_web_service(web_service=new_web_service, user_string=user_string)
            new_services.append(new_web_service)
        return new_services

    def __populate_web_service_scans_for_web_service(self, web_service=None, user_string=None, count=2):
        """
        Populate web service scans for the given web service.
        :param web_service: The web service to populate web service scans for.
        :param user_string: A string depicting the user that is being populated.
        :param count: The number of web service scans to add to the given web service.
        :return: The newly-created web service scans.
        """
        to_return = []
        for i in range(count):
            start_time = timezone.now() - WsFaker.get_timedelta()
            new_scan = web_service.web_service_scans.create(
                started_at=start_time,
            )
            self.__populate_elasticsearch_for_web_service_scan(
                web_service_scan=new_scan,
                is_latest_scan=i == count - 1,
                user_string=user_string,
            )
            to_return.append(new_scan)
        return to_return

    # Properties

    @property
    def bulk_query(self):
        """
        Get the bulk Elasticsearch query to use to populate Elasticsearch data.
        :return: the bulk Elasticsearch query to use to populate Elasticsearch data.
        """
        if self._bulk_query is None:
            self._bulk_query = BulkElasticsearchQuery()
        return self._bulk_query

    # Representation and Comparison
