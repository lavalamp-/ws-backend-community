# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseInspector
from ...mixin import ElasticsearchableMixin
from ...sqlalchemy import IpAddressScan
from wselasticsearch.query import IpPortScanQuery, IpDomainHistoryQuery, IpReverseHostnameQuery, IpGeolocationQuery, \
    IpWhoisQuery
from wselasticsearch.ops import get_all_user_added_domain_names_for_organization


class IpAddressScanInspector(BaseInspector, ElasticsearchableMixin):
    """
    This is an inspector class that is responsible for analyzing the results of a single IP address scan
    for the purpose of creating a single IpAddressReport.
    """

    # Class Members

    # Instantiation

    def __init__(self, ip_address_scan_uuid=None, db_session=None):
        super(IpAddressScanInspector, self).__init__()
        self._ip_address_scan_uuid = ip_address_scan_uuid
        self._ip_address_scan = None
        self._ip_address = None
        self._organization = None
        self._open_tcp_ports = None
        self._open_udp_ports = None
        self._port_scan_results = None
        self._historic_domain_names = None
        self._domain_history_results = None
        self._reverse_domain_names = None
        self._reverse_hostname_results = None
        self._geolocation_results = None
        self._whois_results = None
        self._arin_whois_networks = None
        self._arin_whois_networks_retrieved = False
        self._user_added_domains = None
        self._unknown_domain_names = None
        self.db_session = db_session

    # Static Methods

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import IpAddressReportModel
        return IpAddressReportModel

    # Public Methods

    # Protected Methods

    def _to_es_model(self):
        from wselasticsearch.models import IpAddressReportModel
        return IpAddressReportModel(
            open_tcp_ports=self.open_tcp_ports,
            open_udp_ports=self.open_udp_ports,
            historic_domain_names=self.historic_domain_names,
            reverse_domain_names=self.reverse_domain_names,
            geolocation_geohash=self.geolocation_geohash,
            geolocation_latitude=self.geolocation_latitude,
            geolocation_longitude=self.geolocation_longitude,
            geolocation_region=self.geolocation_region,
            geolocation_country_code=self.geolocation_country_code,
            geolocation_postal_code=self.geolocation_postal_code,
            arin_whois_networks=self.arin_whois_networks,
            unknown_domain_names=self.unknown_domain_names,
        )

    # Private Methods

    def __get_domain_history_results(self):
        """
        Get an Elasticsearch response containing all of the domain history models populated
        during this scan.
        :return: an Elasticsearch response containing all of the domain history models
        populated during this scan.
        """
        query = IpDomainHistoryQuery(max_size=True)
        query.filter_by_ip_address_scan(self.ip_address_scan_uuid)
        return query.search(self.org_uuid)

    def __get_geolocation_results(self):
        """
        Get an Elasticsearch response containing all of the geolocation models retrieved
        during this scan.
        :return: an Elasticsearch response containing all of the geolocation models
        retrieved during this scan.
        """
        query = IpGeolocationQuery(max_size=True)
        query.filter_by_ip_address_scan(self.ip_address_scan_uuid)
        return query.search(self.org_uuid)

    def __get_port_scan_results(self):
        """
        Get an Elasticsearch response containing all of the IpPortScanModel objects created during
        this IP address scan.
        :return: an Elasticsearch response containing all of the IpPortScanModel objects created
        during this IP address scan.
        """
        query = IpPortScanQuery(max_size=True)
        query.filter_by_ip_address_scan(self.ip_address_scan_uuid)
        return query.search(self.org_uuid)

    def __get_reverse_hostname_results(self):
        """
        Get an Elasticsearch response containing all of the IpReverseHostnameModel objects
        populated during this scan.
        :return: an Elasticsearch response containing all of the IpReverseHostnameModel
        objects populated during this scan.
        """
        query = IpReverseHostnameQuery(max_size=True)
        query.filter_by_ip_address_scan(self.ip_address_scan_uuid)
        return query.search(self.org_uuid)

    def __get_whois_results(self):
        """
        Get an Elasticsearch response containing all of the IpWhoisModel data retrieved during this scan.
        :return: an Elasticsearch response containing all of the IpWhoisModel data retrieved during this scan.
        """
        query = IpWhoisQuery(max_size=True)
        query.filter_by_ip_address_scan(self.ip_address_scan_uuid)
        return query.search(self.org_uuid)

    def __is_unknown_domain(self, domain_name):
        """
        Check to see if the given domain name is one of the known domain names associated with self.organization.
        :param domain_name: The domain name to check.
        :return: True if the domain name is an unknown domain, False otherwise.
        """
        domain_name = domain_name.lower()
        for check_domain in self.user_added_domains:
            if domain_name.endswith(check_domain.lower()):
                return True
        return False

    # Properties

    @property
    def arin_whois_networks(self):
        """
        Get a list of dictionaries describing the ARIN networks associated with this IP address.
        :return: a list of dictionaries describing the ARIN networks associated with this IP address.
        """
        if self._arin_whois_networks is None:
            networks = []
            for result in self.arin_whois_results:
                networks.append({
                    "whois_org_name": result["_source"]["whois_org_name"],
                    "whois_org_handle": result["_source"]["whois_org_handle"],
                    "whois_org_country_code": result["_source"]["whois_org_country_code"],
                    "whois_network_handle": result["_source"]["whois_network_handle"],
                    "whois_network_name": result["_source"]["whois_network_name"],
                    "whois_network_range": result["_source"]["whois_network_range"],
                })
            self._arin_whois_networks = networks
        return self._arin_whois_networks

    @property
    def arin_whois_results(self):
        """
        Get a list containing the WHOIS results data retrieved from ARIN.
        :return: A list containing the WHOIS results data retrieved from ARIN.
        """
        return filter(lambda x: x["_source"]["whois_data_source"] == "arin", self.whois_results.results)

    @property
    def domain_history_results(self):
        """
        Get an Elasticsearch response containing all of the domain history models populated
        during this scan.
        :return: an Elasticsearch response containing all of the domain history models
        populated during this scan.
        """
        if self._domain_history_results is None:
            self._domain_history_results = self.__get_domain_history_results()
        return self._domain_history_results

    @property
    def geolocation_country_code(self):
        """
        Get the country_code of the preferred geolocation for this IP address.
        :return: the country_code of the preferred geolocation for this IP address.
        """
        return self.preferred_geolocation["_source"]["country_code"] if self.preferred_geolocation else None

    @property
    def geolocation_geohash(self):
        """
        Get the geohash of the preferred geolocation for this IP address.
        :return: the geohash of the preferred geolocation for this IP address.
        """
        return self.preferred_geolocation["_source"]["geolocation"] if self.preferred_geolocation else None

    @property
    def geolocation_latitude(self):
        """
        Get the latitude of the preferred geolocation for this IP address.
        :return: the latitude of the preferred geolocation for this IP address.
        """
        return self.preferred_geolocation["_source"]["latitude"] if self.preferred_geolocation else None

    @property
    def geolocation_longitude(self):
        """
        Get the longitude of the preferred geolocation for this IP address.
        :return: the longitude of the preferred geolocation for this IP address.
        """
        return self.preferred_geolocation["_source"]["longitude"] if self.preferred_geolocation else None

    @property
    def geolocation_postal_code(self):
        """
        Get the postal_code of the preferred geolocation for this IP address.
        :return: the postal_code of the preferred geolocation for this IP address.
        """
        return self.preferred_geolocation["_source"]["postal_code"] if self.preferred_geolocation else None

    @property
    def geolocation_region(self):
        """
        Get the region of the preferred geolocation for this IP address.
        :return: the region of the preferred geolocation for this IP address.
        """
        return self.preferred_geolocation["_source"]["region"] if self.preferred_geolocation else None

    @property
    def geolocation_results(self):
        """
        Get an Elasticsearch response containing all of the geolocation models retrieved
        during this scan.
        :return: an Elasticsearch response containing all of the geolocation models
        retrieved during this scan.
        """
        if self._geolocation_results is None:
            self._geolocation_results = self.__get_geolocation_results()
        return self._geolocation_results

    @property
    def historic_domain_names(self):
        """
        Get a list of strings containing all of the domain names found to point to the IP
        address during the scan.
        :return: a list of strings containing all of the domain names found to point to
        the IP address during the scan.
        """
        if self._historic_domain_names is None:
            historic_domain_names = set()
            for result in self.domain_history_results.results:
                historic_domain_names = historic_domain_names.union(result["_source"]["domain_names"])
            self._historic_domain_names = list(historic_domain_names)
        return self._historic_domain_names

    @property
    def inspection_target(self):
        return self.ip_address_scan_uuid

    @property
    def ip_address_scan(self):
        """
        Get the IP address scan object that this object is responsible for analyzing.
        :return: the IP address scan object that this object is responsible for analyzing.
        """
        if self._ip_address_scan is None:
            self._ip_address_scan = IpAddressScan.by_uuid(uuid=self.ip_address_scan_uuid, db_session=self.db_session)
        return self._ip_address_scan

    @property
    def ip_address_scan_uuid(self):
        """
        Get the UUID of the IP address scan that this object is responsible for analyzing.
        :return: the UUID of the IP address scan that this object is responsible for analyzing.
        """
        return self._ip_address_scan_uuid

    @property
    def ip_address(self):
        """
        Get the IP address model that was scanned.
        :return: the IP address model that was scanned.
        """
        if self._ip_address is None:
            self._ip_address = self.ip_address_scan.ip_address
        return self._ip_address

    @property
    def ip_address_uuid(self):
        """
        Get the UUID of the IP address that was scanned during the analyzed scan.
        :return: the UUID of the IP address that was scanned during the analyzed scan.
        """
        return self.ip_address.uuid

    @property
    def open_tcp_ports(self):
        """
        Get a list of integers representing the TCP ports that were found to be open on the IP address.
        :return: a list of integers representing the TCP ports that were found to be open on the IP address.
        """
        if self._open_tcp_ports is None:
            open_tcp_ports = set()
            for result in self.port_scan_results.results:
                for port_result in result["_source"]["port_results"]:
                    if port_result["port_protocol"] == "tcp" and port_result["port_status"] == "open":
                        open_tcp_ports.add(port_result["port_number"])
            self._open_tcp_ports = list(open_tcp_ports)
        return self._open_tcp_ports

    @property
    def open_udp_ports(self):
        """
        Get a list of integers representing the UDP ports that were found to be open on the IP address.
        :return: a list of integers representing the UDP ports that were found to be open on the IP address.
        """
        if self._open_udp_ports is None:
            open_udp_ports = set()
            for result in self.port_scan_results.results:
                for port_result in result["_source"]["port_results"]:
                    if port_result["port_protocol"] == "udp" and port_result["port_status"] == "open":
                        open_udp_ports.add(port_result["port_number"])
            self._open_udp_ports = list(open_udp_ports)
        return self._open_udp_ports

    @property
    def organization(self):
        """
        Get the organization that owns the scanned IP address.
        :return: the organization that owns the scanned IP address.
        """
        return self.ip_address.network.organization

    @property
    def org_uuid(self):
        """
        Get the UUID of the organization that owns the scanned IP address.
        :return: the UUID of the organization that owns the scanned IP address.
        """
        return self.organization.uuid

    @property
    def port_scan_results(self):
        """
        Get an Elasticsearch response containing all of the IpPortScanModel objects created during
        this IP address scan.
        :return: an Elasticsearch response containing all of the IpPortScanModel objects created
        during this IP address scan.
        """
        if self._port_scan_results is None:
            self._port_scan_results = self.__get_port_scan_results()
        return self._port_scan_results

    @property
    def preferred_geolocation(self):
        """
        Get the geolocation result that is preferred to use for geolocation data.
        :return: the geolocation result that is preferred to use for geolocation data if such a geolocation result
        exists, otherwise None.
        """
        return self.geolocation_results.results[0] if self.geolocation_results.results_count > 0 else None

    @property
    def reverse_domain_names(self):
        """
        Get a list of domain names that point to the scanned IP address.
        :return: a list of domain names that point to the scanned IP address.
        """
        if self._reverse_domain_names is None:
            reverse_domain_names = set()
            for result in self.reverse_hostname_results.results:
                reverse_domain_names = reverse_domain_names.union(result["_source"]["hostnames"])
            self._reverse_domain_names = list(reverse_domain_names)
        return self._reverse_domain_names

    @property
    def reverse_hostname_results(self):
        """
        Get an Elasticsearch response containing all of the IpReverseHostnameModel objects
        populated during this scan.
        :return: an Elasticsearch response containing all of the IpReverseHostnameModel
        objects populated during this scan.
        """
        if self._reverse_hostname_results is None:
            self._reverse_hostname_results = self.__get_reverse_hostname_results()
        return self._reverse_hostname_results

    @property
    def unknown_domain_names(self):
        """
        Get a list of strings representing the domains that point to this IP address that a user has
        not explicitly added to the related organization.
        :return: a list of strings representing the domains that point to this IP address that a user
        has not explicitly added to the related organization.
        """
        if self._unknown_domain_names is None:
            unknown_domain_names = set()
            for domain_name in self.reverse_domain_names:
                if self.__is_unknown_domain(domain_name):
                    unknown_domain_names.add(domain_name)
            for domain_name in self.historic_domain_names:
                if self.__is_unknown_domain(domain_name):
                    unknown_domain_names.add(domain_name)
            self._unknown_domain_names = list(unknown_domain_names)
        return self._unknown_domain_names

    @property
    def user_added_domains(self):
        """
        Get a list of strings representing all of the domains associated with this IP address's organization
        that were added by a user.
        :return: a list of strings representing all of the domains associated with this IP address's
        organization that were added by a user.
        """
        if self._user_added_domains is None:
            self._user_added_domains = get_all_user_added_domain_names_for_organization(org_uuid=self.org_uuid)
        return self._user_added_domains

    @property
    def whois_results(self):
        """
        Get an Elasticsearch response containing all of the IpWhoisModel data retrieved during this scan.
        :return: an Elasticsearch response containing all of the IpWhoisModel data retrieved during this scan.
        """
        if self._whois_results is None:
            self._whois_results = self.__get_whois_results()
        return self._whois_results

    # Representation and Comparison
