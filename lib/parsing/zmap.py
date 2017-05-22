# -*- coding: utf-8 -*-
from __future__ import absolute_import

from netaddr import IPNetwork

from lib import ConversionHelper
from .base import BaseFileParser
from .wrappers import ZmapCsvWrapper


class ZmapCsvParser(BaseFileParser):
    """
    This class is meant to parse the contents of a Zmap CSV output file.
    """

    # Class Members

    _wrapper = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def count_class_c_networks(self):
        """
        Get the total number of class C networks that would be required to cover all live
        hosts found through the Zmap scan.
        :return: The total number of class C networks that would be required to cover all live
        hosts found through the Zmap scan.
        """
        return len(self.get_class_c_cidr_tuples())

    def count_live_hosts(self):
        """
        Get the number of live hosts that were found as a result of the Zmap scan that generated the
        wrapped output file.
        :return: The number of live hosts that were found as a result of the Zmap scan that generated the
        wrapped output file.
        """
        return len(self.csv_wrapper.scan_results.keys())

    def get_class_c_cidr_tuples(self):
        """
        Get a list of tuples containing (1) the CIDR prefix as a string and (2) the CIDR mask length as
        an integer for all class C networks found to contain the results the wrapped Zmap CSV file.
        :return: A list of tuples containing (1) the CIDR prefix as a string and (2) the CIDR mask length as
        an integer for all class C networks found to contain the results the wrapped Zmap CSV file.
        """
        live_ips = self.get_live_ips()
        return list(set([ConversionHelper.ipv4_to_class_c_cidr_tuple(live_ip) for live_ip in live_ips]))

    def get_class_c_networks(self):
        """
        Get a list of IPNetwork objects that represent the minimum number of class C networks
        that cover all of the IP addresses found in the referenced CSV file.
        :return: A list of IPNetwork objects that represent the minimum number of class C networks
        that cover all of the IP addresses found in the referenced CSV file.
        """
        live_ips = self.get_live_ips()
        live_networks = [ConversionHelper.ipv4_to_class_c(live_ip) for live_ip in live_ips]
        return [IPNetwork(x) for x in set(live_networks)]

    def get_live_ips(self):
        """
        Get a list of the IP addresses found within the referenced Zmap CSV file.
        :return: A list of the IP addresses found within the referenced Zmap CSV file.
        """
        return self.csv_wrapper.scan_results.keys()

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def parse_type(self):
        return "Zmap CSV Output File"

    @property
    def csv_wrapper(self):
        if self._wrapper is None:
            self._wrapper = ZmapCsvWrapper(self.file_contents)
        return self._wrapper

    # Representation and Comparison
