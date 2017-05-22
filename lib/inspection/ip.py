# -*- coding: utf-8 -*-
from __future__ import absolute_import

import socket
from netaddr import IPNetwork

from lib.tools import NmapScanner
from .base import BaseInspector
from ..arin.request import NetworksArinRequest, NetworkArinRequest
from ..geolocation import IpGeolocator
from lib import FilesystemHelper


class IpAddressInspector(BaseInspector):
    """
    Documentation for IpAddressInspector.
    """

    # Class Members

    # Instantiation

    def __init__(self, ip_address=None, address_type="ipv4"):
        self._ip_address = ip_address
        self._address_type = address_type
        self._geolocator = None
        super(IpAddressInspector, self).__init__()

    # Static Methods

    # Class Methods

    # Public Methods

    def get_geolocations(self, use_class_c=True):
        """
        Get a list of IpGeolocation objects representing geolocation data for this IP address as retrieved
        from all geolocation sources integrated in Web Sight.
        :param use_class_c: Whether or not to use the IP address of the containing class C network for the
        wrapped IP address.
        :return: A list of IpGeolocation objects representing geolocation data for this IP address as retrieved
        from all geolocation sources integrated in Web Sight.
        """
        queried_ip = self.class_c_address if use_class_c else self.ip_address
        return self.geolocator.get_geolocations_for_ip_address(queried_ip)

    def get_hostnames(self):
        """
        Get a list of hostnames referencing the given IP address.
        :return: A list of hostnames referencing the given IP address.
        """
        try:
            response = socket.gethostbyaddr(self.ip_address)
            to_return = set()
            to_return.add(response[0])
            to_return = to_return.union(response[1])
            return list(to_return)
        except socket.herror:
            return []

    def get_arin_related_networks(self, full_details=True, use_class_c=True):
        """
        Get a list of ARIN networks associated with this IP address.
        :param full_details: Whether or not to retrieve the full details of the queried networks, or just to
        return summary details.
        :param use_class_c: Whether or not to request information about this specific IP address or the class C
        network that it resides in.
        :return: A list of ARIN networks associated with this IP address.
        """
        if use_class_c:
            queried_ip = self.class_c_address
        else:
            queried_ip = self.ip_address
        networks = NetworksArinRequest.get_networks_by_ip_address(queried_ip).networks
        if full_details:
            to_return = []
            for network in networks:
                to_return.append(NetworkArinRequest.get(network.handle).network)
            return to_return
        else:
            return networks

    def scan_for_open_tcp_ports(self, ports=None, db_session=None):
        """
        Scan the wrapped IP address for open services on the list of ports.
        :param ports: A list of integers representing the ports to scan.
        :param db_session: A SQLAlchemy session.
        :return: A list of the ports found to be open.
        """
        nmap_scanner = NmapScanner.from_default_configuration(db_session)
        nmap_scanner.add_ports(ports)
        nmap_scanner.add_ipv4_address(self.ip_address)
        temp_path = FilesystemHelper.get_temporary_file_path()
        nmap_scanner.output_file_path = temp_path
        nmap_scanner.scan_type = "tcp connect"
        nmap_scanner.run()
        results_wrapper = nmap_scanner.get_results_parser()
        results = results_wrapper.get_results_for_ip_address(self.ip_address)
        if not results:
            to_return = []
        else:
            to_return = [x.port_number for x in results.open_ports]
        extensions = [".xml", ".gnmap", ".nmap"]
        for extension in extensions:
            FilesystemHelper.delete_file("%s%s" % (temp_path, extension))
        return to_return

    def scan_for_open_udp_ports(self, ports=None, db_session=None):
        """
        Scan the wrapped IP address for open services on the list of ports.
        :param ports: A list of integers representing the ports to scan.
        :param db_session: A SQLAlchemy session.
        :return: A list of the ports found to be open.
        """
        nmap_scanner = NmapScanner.from_default_configuration(db_session)
        nmap_scanner.add_ports(ports)
        nmap_scanner.add_ipv4_address(self.ip_address)
        temp_path = FilesystemHelper.get_temporary_file_path()
        nmap_scanner.output_file_path = temp_path
        nmap_scanner.scan_type = "udp"
        nmap_scanner.run()
        results_wrapper = nmap_scanner.get_results_parser()
        results = results_wrapper.get_results_for_ip_address(self.ip_address)
        if not results:
            to_return = []
        else:
            to_return = [x.port_number for x in results.open_ports]
        extensions = [".xml", ".gnmap", ".nmap"]
        for extension in extensions:
            FilesystemHelper.delete_file("%s%s" % (temp_path, extension))
        return to_return

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def address_type(self):
        """
        Get a string describing the address type that self.ip_address represents.
        :return: a string describing the address type that self.ip_address represents.
        """
        return self._address_type

    @property
    def class_a_address(self):
        """
        Get the starting IP address of the class A network that contains this IP address.
        :return: the starting IP address of the class A network that contains this IP address.
        """
        return str(self.containing_class_a.cidr.ip)

    @property
    def class_b_address(self):
        """
        Get the starting IP address of the class B network that contains this IP address.
        :return: the starting IP address of the class B network that contains this IP address.
        """
        return str(self.containing_class_b.cidr.ip)

    @property
    def class_c_address(self):
        """
        Get the starting IP address of the class C network that contains this IP address.
        :return: the starting IP address of the class C network that contains this IP address.
        """
        return str(self.containing_class_c.cidr.ip)

    @property
    def containing_class_a(self):
        """
        Get the class A network that contains this IP address.
        :return: the class A network that contains this IP address.
        """
        return IPNetwork("%s/8" % self.ip_address)

    @property
    def containing_class_b(self):
        """
        Get the class B network that contains this IP address.
        :return: the class B network that contains this IP address.
        """
        return IPNetwork("%s/16" % self.ip_address)

    @property
    def containing_class_c(self):
        """
        Get the class C network that contains this IP address.
        :return: the class C network that contains this IP address.
        """
        return IPNetwork("%s/24" % self.ip_address)

    @property
    def geolocator(self):
        """
        Get an instance of IpGeolocator to use for collecting geolocation data.
        :return: an instance of IpGeolocator to use for collecting geolocation data.
        """
        if self._geolocator is None:
            self._geolocator = IpGeolocator()
        return self._geolocator

    @property
    def inspection_target(self):
        return self.ip_address

    @property
    def ip_address(self):
        """
        Get the IP address this inspector is intended to investigate.
        :return: the IP address this inspector is intended to investigate.
        """
        return self._ip_address

    # Representation and Comparison
