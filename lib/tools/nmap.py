# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
from netaddr import IPAddress, IPRange, IPNetwork, cidr_merge
from datetime import datetime

from lib import ValidationHelper, FilesystemHelper
from .base import BaseNetworkScannerRunner

logger = logging.getLogger(__name__)


class NmapScanner(BaseNetworkScannerRunner):
    """
    This class contains methods for controlling Nmap scanning functionality.
    """

    # Class Members

    _ipv4_addresses = None
    _ipv4_networks = None
    _ipv4_ranges = None
    _network_ranges = None
    _output_file_path = None
    _port_ranges = None
    _ports = None
    _scan_all_ports = None
    _scan_type = None
    _speed = None
    _resolution_enabled = None
    _fingerprinting_enabled = None
    _host_discovery_enabled = None
    _output_type = None

    # Instantiation

    def __init__(self):
        """
        Initialize this NmapScanner to have the intended initial internal state.
        """
        self.reset()

    # Static Methods

    # Class Methods

    @classmethod
    def get_configuration_class(cls):
        from lib.sqlalchemy import NmapConfig
        return NmapConfig

    @classmethod
    def _from_configuration(cls, tool_config):
        to_return = NmapScanner()
        to_return.speed = tool_config.speed
        to_return.output_type = tool_config.output_type
        to_return.fingerprinting_enabled = tool_config.fingerprinting_enabled
        to_return.resolution_enabled = tool_config.resolution_enabled
        to_return.host_discovery_enabled = tool_config.host_discovery_enabled
        return to_return

    # Public Methods

    def add_ipv4_address(self, ipv4_address):
        """
        Add the specified IPv4 address to the list of addresses to scan.
        :param ipv4_address: The IPv4 address to scan.
        :return: None
        """
        ValidationHelper.validate_ipv4_address(ipv4_address)
        self._ipv4_addresses.add(ipv4_address)

    def add_ipv4_network(self, network):
        """
        Add the specified IPv4 CIDR range to the list of IP ranges to scan.
        :param network: The CIDR network to add.
        :return: None
        """
        ValidationHelper.validate_ipv4_cidr(network)
        self._ipv4_networks.add(network)

    def add_ipv4_range(self, start=None, end=None):
        """
        Add the specified IPv4 address range to the list of addresses to scan.
        :param start: The start of the IPv4 address range.
        :param end: The end of the IPv4 address range.
        :return: None
        """
        ValidationHelper.validate_ipv4_address(start)
        ValidationHelper.validate_ipv4_address(end)
        start_addr = IPAddress(start)
        end_addr = IPAddress(end)
        if end_addr <= start_addr:
            raise ValueError(
                "NmapScanner.add_ipv4_range received an end value (%s) less than its start value (%s)."
                % (end, start)
            )
        self._ipv4_ranges.add((start, end))

    def add_port(self, port):
        """
        Add the specified port to the list of ports to scan.
        :param port: The port to add
        :return: None
        """
        ValidationHelper.validate_port(port)
        self._ports.add(port)

    def add_ports(self, ports):
        """
        Add the specified ports to the list of ports to scan.
        :param ports: A list of integers representing ports to scan.
        :return: None
        """
        for port in ports:
            self.add_port(port)

    def add_port_range(self, start=None, end=None):
        """
        Add the specified range of ports to the ports to scan
        :param start: The beginning of the range.
        :param end: The end of the range (inclusive).
        :return: None
        """
        ValidationHelper.validate_port_range(start=start, end=end)
        start = int(start)
        end = int(end)
        self._port_ranges.add((start, end))

    def count_target_ips(self):
        """
        Count the number of IP addresses this scanner is configured to scan.
        :return: The number of IP addresses this scanner is configured to scan.
        """
        return len(self.get_all_ips())

    def count_target_ports(self):
        """
        Count the number of ports this scanner is configured to scan.
        :return: The number of ports this scanner is configured to scan.
        """
        if self.scan_all_ports:
            return 65535
        else:
            to_scan = set()
            to_scan = to_scan.union(self.ports)
            for range_start, range_end in self.port_ranges:
                to_scan = to_scan.union(range(range_start, range_end + 1))
            return len(to_scan)

    def count_target_services(self):
        """
        Count the total number of network services this scanner is currently
        configured to scan.
        :return: The total number of network services this scanner is currently
        configured to scan.
        """
        return self.count_target_ips() * self.count_target_ports()

    def disable_dns_resolution(self):
        """
        Configure this scanner to not perform DNS resolution.
        :return: None
        """
        self.resolution_enabled = False

    def disable_fingerprinting(self):
        """
        Configure this scanner not to perform service fingerprinting.
        :return: None
        """
        self.fingerprinting_enabled = False

    def disable_host_discovery(self):
        """
        Configure this scanner to not perform host discovery.
        :return: None
        """
        self.host_discovery_enabled = False

    def enable_dns_resolution(self):
        """
        Configure this scanner to perform DNS resolution.
        :return: None
        """
        self.resolution_enabled = True

    def enable_fingerprinting(self):
        """
        Configure this scanner to perform service fingerprinting.
        :return: None
        """
        self.fingerprinting_enabled = True

    def enable_host_discovery(self):
        """
        Configure this scanner to enable host discovery.
        :return: None
        """
        self.host_discovery_enabled = True

    def get_output_file_argument(self):
        """
        Get a string representing the output file settings as passed to the Nmap
        command line.
        :return: A string representing the output file settings as passed to the Nmap
        command line.
        """
        return "-o%s %s" % (self.output_type_string, self.get_output_file_name())

    def get_output_file_name(self):
        """
        Get the file name that results should be written to. Note that this will
        first check to see if such a file name has already been set and return it
        if it has, and second will use a temporary file name that us guaranteed to be
        writable if it has not.
        :return: The file name that results should be written to.
        """
        if self.output_file_path is not None:
            return self.output_file_path
        else:
            return FilesystemHelper.get_temporary_file_path()

    def get_all_ips(self):
        """
        Get a list that can be iterated over that includes every IP address currently
        configured in this scanner.
        :return: A list that can be iterated over that includes every IP address currently
        configured in this scanner.
        """
        to_return = []
        for address in self.ipv4_addresses:
            to_return.append(IPAddress(address))
        for range_start, range_end in self.ipv4_ranges:
            to_return.append(IPRange(range_start, range_end))
        for network in self.ipv4_networks:
            to_return.append(IPNetwork(network))
        return to_return

    def get_scanner_flags(self):
        """
        Get a list of strings to use as flags for the underlying Nmap scanner.
        :return: A list of strings to use as flags for the underlying Nmap scanner.
        """
        to_return = [self.scan_type_flag]
        if not self.host_discovery_enabled:
            to_return.append("-Pn")
        if not self.enable_dns_resolution:
            to_return.append("-n")
        if self.fingerprinting_enabled:
            to_return.append("-A")
        to_return.append("-T%s" % (self.speed,))
        return to_return

    def get_scanner_flags_string(self):
        """
        Get a string representing the flags that should be passed to this Nmap command
        line representing the current configuration of this scanner.
        :return: A string representing the flags that should be passed to this Nmap command
        line representing the current configuration of this scanner.
        """
        return " ".join(self.get_scanner_flags())

    def get_scanner_ports_string(self):
        """
        Get a string representing the ports that this scanner is configured to scan.
        :return: A string representing the ports that this scanner is configured to scan.
        """
        port_specs = []
        port_specs.extend([str(x) for x in self.ports])
        for start_port, end_port in self.port_ranges:
            port_specs.append("%s-%s" % (start_port, end_port))
        return ",".join(port_specs)

    def get_scanner_targets(self):
        """
        Get a list of strings representing the IP addresses and network ranges that
        this scanner is configured to scan.
        :return: A list of strings representing the IP addresses and network ranges that
        this scanner is configured to scan.
        """
        all_ips = self.get_all_ips()
        merged = cidr_merge(all_ips)
        return [str(x) for x in merged]

    def get_scanner_targets_string(self):
        """
        Get a string representing the targets configured to be scanned by this scanner
        (as passed to the Nmap command line).
        :return: A string representing the targets configured to be scanned by this scanner
        (as passed to the Nmap command line).
        """
        return " ".join(self.get_scanner_targets())

    def reset(self):
        """
        Reset the internal state of this Nmap scanner.
        :return: None
        """
        self._ports = set()
        self._port_ranges = set()
        self._network_ranges = set()
        self._output_file_path = None
        self._scan_type = "tcp connect"
        self._ipv4_addresses = set()
        self._ipv4_ranges = set()
        self._scan_all_ports = False
        self._ipv4_networks = set()
        self._speed = 3
        self._resolution_enabled = True
        self._fingerprinting_enabled = False
        self._host_discovery_enabled = True
        self._output_type = "all"

    def set_type_to_syn(self):
        """
        Set this NmapScanner to perform a TCP SYN scan.
        :return: None
        """
        self.scan_type = "tcp syn"

    def set_type_to_tcp_connect(self):
        """
        Set this NmapScanner to perform a TCP full connect scan.
        :return: None
        """
        self.scan_type = "tcp connect"

    def set_type_to_udp(self):
        """
        Get this NmapScanner to perform a UDP scan.
        :return: None
        """
        self.scan_type = "udp"

    def toggle_dns_resolution(self):
        """
        Change the current state of DNS resolution configuration in this
        scanner to the state it currently is not.
        :return: None
        """
        self.resolution_enabled = not self.resolution_enabled

    def toggle_fingerprinting(self):
        """
        Change the state of the current scanner configuration's fingerprinting
        to the stateit currently is not.
        :return: None
        """
        self.fingerprinting_enabled = not self.fingerprinting_enabled

    def toggle_host_discovery(self):
        """
        Change the state of the current scanner configuration's host discovery
        to the state it currently is not.
        :return: None
        """
        self.host_discovery_enabled = not self.host_discovery_enabled

    # Protected Methods

    def _get_command_line_flags(self):
        to_return = []
        to_return.append(("-s%s" % self.scan_type_string,))
        if self.fingerprinting_enabled:
            to_return.append(("-A",))
        if not self.resolution_enabled:
            to_return.append(("-n",))
        if not self.host_discovery_enabled:
            to_return.append(("-Pn",))
        if self.scan_all_ports:
            to_return.append(("-p-",))
        else:
            to_return.append(("-p", self.get_scanner_ports_string()))
        to_return.append(("-o%s" % self.output_type_string, self.output_file_path,))
        to_return.append(("-T", self.speed))
        to_return.append((self.get_scanner_targets_string(),))
        return to_return

    def _is_tool_ready(self):
        errors = []
        if self.output_file_path is None:
            errors.append("No output file specified")
        if self.count_target_ips() == 0:
            errors.append("No IP addresses specified")
        if self.count_target_ports() == 0:
            errors.append("No ports specified")
        return not bool(errors), errors

    def _get_results_parser(self):
        from lib.parsing import NmapXmlWrapper
        return NmapXmlWrapper.from_file("%s.xml" % self.output_file_path)

    def _set_to_scan_tcp(self):
        self.scan_type = "tcp connect"

    def _set_to_scan_udp(self):
        self.scan_type = "udp"

    # Private Methods

    # Properties

    @property
    def command(self):
        return "nmap"

    @property
    def fingerprinting_enabled(self):
        """
        Get whether or not the scanner is configured to perform
        service fingerprinting.
        :return: True if the scanner is configured to perform service
        fingerprinting, False otherwise.
        """
        return self._fingerprinting_enabled

    @fingerprinting_enabled.setter
    def fingerprinting_enabled(self, new_value):
        """
        Set whether or not the scanner should perform service fingerprinting.
        :param new_value: The value to set self._fingerprinting_enabled to.
        :return: None
        """
        if not isinstance(new_value, bool):
            raise ValueError(
                "NmapScanner.fingerprinting_enabled setter received an unexpected value: %s."
                % (new_value,)
            )
        self._fingerprinting_enabled = new_value

    @property
    def host_discovery_enabled(self):
        """
        Get whether or not this scanner is configured to perform host discovery.
        :return: True if this scanner is configured to perform host discovery, False
        otherwise.
        """
        return self._host_discovery_enabled

    @host_discovery_enabled.setter
    def host_discovery_enabled(self, new_value):
        """
        Set whether or not this scanner should perform host discovery.
        :param new_value: The new value to set self._host_discovery_enabled to.
        :return: None
        """
        if not isinstance(new_value, bool):
            raise ValueError(
                "NmapScanner.host_discovery_enabled setter received an unexpected value: %s."
                % (new_value,)
            )
        self._host_discovery_enabled = new_value

    @property
    def ipv4_addresses(self):
        """
        Get a list of IPv4 addresses to scan.
        :return: A list of IPv4 addresses to scan.
        """
        return list(self._ipv4_addresses)

    @property
    def ipv4_networks(self):
        """
        Get a list of the IP networks to scan.
        :return: A list of the IP networks to scan.
        """
        return list(self._ipv4_networks)

    @property
    def ipv4_ranges(self):
        """
        Get a list of tuples describing IPv4 ranges to scan.
        :return: A list of tuples describing IPv4 ranges to scan.
        """
        return list(self._ipv4_ranges)

    @property
    def network_ranges(self):
        """
        Get a list of tuples describing the ranges to scan.
        :return: A list of tuples describing the ranges to scan.
        """
        return list(self._network_ranges)

    @property
    def output_file_path(self):
        """
        Get the name of the file to write to.
        :return: The name of the file to write to.
        """
        return self._output_file_path

    @output_file_path.setter
    def output_file_path(self, new_value):
        """
        Set the value of the file name to write to.
        :param new_value: The new file name to write to.
        :return: None
        """
        self._output_file_path = new_value

    @property
    def output_type(self):
        """
        Get the type of file that the Nmap scan results should be written to.
        :return: A constant depicting the type of file that the Nmap scan results
        should be written to.
        """
        return self._output_type

    @output_type.setter
    def output_type(self, new_value):
        """
        Set the type of file that the Nmap scan results should be written to.
        :param new_value: The type of file that the scan results should be written to.
        :return: None
        """
        ValidationHelper.validate_nmap_output_type(new_value)
        self._output_type = new_value

    @property
    def output_type_string(self):
        """
        Get a string representing the command line flag to pass to Nmap for writing to
        the configured file type.
        :return: A string representing the command line flag to pass to Nmap for writing to
        the configured file type.
        """
        if self.output_type == "nmap":
            return "N"
        elif self.output_type == "gnmap":
            return "G"
        elif self.output_type == "xml":
            return "X"
        elif self.output_type == "all":
            return "A"
        else:
            raise ValueError(
                "No string mapping found for output_type of %s."
                % (self.output_type,)
            )

    @property
    def port_ranges(self):
        """
        Get a list of tuples describing the port ranges to scan.
        :return: A list of tuples describing the port ranges to scan.
        """
        return list(self._port_ranges)

    @property
    def ports(self):
        """
        Get the list of ports that this NmapScanner is currently configured to scan.
        :return: The list of ports that this NmapScanner is currently configured to scan.
        """
        return list(self._ports)

    @property
    def resolution_enabled(self):
        """
        Get whether the currently configured scan is set to perform DNS resolution.
        :return: True if the currently configured scan is set to perform DNS
        resolution, False otherwise.
        """
        return self._resolution_enabled

    @resolution_enabled.setter
    def resolution_enabled(self, new_value):
        """
        Set the value of self._resolution_enabled.
        :param new_value: The new value to set self._resolution_enabled to.
        :return: None
        """
        if not isinstance(new_value, bool):
            raise ValueError(
                "NmapScanner.resolution_enabled setter received an unexpected value: %s."
                % (new_value,)
            )
        self._resolution_enabled = new_value

    @property
    def scan_all_ports(self):
        """
        Get whether or not this scanner is configured to scan all ports on the target
        ranges.
        :return: True if this scanner is configured to scan all ports on the target
        ranges, False otherwise.
        """
        return self._scan_all_ports

    @scan_all_ports.setter
    def scan_all_ports(self, new_value):
        """
        Set the value of self._scan_all_ports.
        :param new_value: The new value to associate with self._scan_all_ports.
        :return: None
        """
        if not isinstance(new_value, bool):
            raise ValueError(
                "Unexpected value passed to NmapScanner.scan_all_ports setter: %s."
                % (new_value,)
            )
        self._scan_all_ports = new_value

    @property
    def scan_type(self):
        """
        Get the scan type that this scanner is configured to perform.
        :return: The scan type that this scanner is configured to perform.
        """
        return self._scan_type

    @scan_type.setter
    def scan_type(self, new_value):
        """
        Set the scan type that this scanner is configured to perform.
        :param new_value: The new value to set the scan type to.
        :return: None
        """
        ValidationHelper.validate_nmap_scan_type(new_value)
        self._scan_type = new_value

    @property
    def scan_type_flag(self):
        """
        Get a string representing the command line argument passed to the Nmap
        command line that dictates what type of scan should be run.
        :return: A string representing the command line argument passed to the Nmap
        command line that dictates what type of scan should be run.
        """
        return "-s%s" % (self.scan_type_string,)

    @property
    def scan_type_string(self):
        """
        Get a string representing the scan type as used in the Nmap command line.
        :return: A string representing the scan type as used in the Nmap command line.
        """
        if self.scan_type == "tcp connect":
            return "T"
        elif self.scan_type == "udp":
            return "U"
        elif self.scan_type == "tcp syn":
            return "S"
        else:
            raise ValueError(
                "No mapping exists for scan type of %s."
                % (self.scan_type,)
            )

    @property
    def speed(self):
        """
        Get the speed this scanner is configured to run the scan at.
        :return: The speed this scanner is configured to run the scan at.
        """
        return self._speed

    @speed.setter
    def speed(self, new_value):
        """
        Set the speed this scanner should scan at.
        :param new_value: The speed this scanner should scan at.
        :return: None
        """
        ValidationHelper.validate_nmap_speed(new_value)
        self._speed = new_value

    @property
    def tool_name(self):
        return "Nmap"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s hosts, %s ports, %s total endpoints>" \
            % (
                self.__class__.__name__,
                self.count_target_ips(),
                self.count_target_ports(),
                self.count_target_services(),
            )
