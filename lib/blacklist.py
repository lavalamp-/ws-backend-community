# -*- coding: utf-8 -*-
from __future__ import absolute_import

from netaddr import IPAddress, IPNetwork, IPRange

from .singleton import Singleton
from .filesystem import FilesystemHelper
from .config import ConfigManager

config = ConfigManager.instance()


@Singleton
class IPBlacklist(object):
    """
    A class containing methods for determining whether or not IP
    addresses (as represented by strings) reside on the blacklist
    of IP addresses that DataHound should not touch.
    """

    # Class Members

    # Instantiation

    def __init__(self):
        """
        Creates the IPBlacklist object from the contents of the
        IP blacklist file as specified by the DataHound configuration.
        :return: None
        """
        self._blacklist_entries = []
        contents = FilesystemHelper.get_file_contents(path=config.files_networks_blacklist_path)
        for cur_line in [x.strip() for x in contents.strip().split("\n")]:
            if not cur_line.startswith("#"):
                self._blacklist_entries.append(IPBlacklistEntry(cur_line))

    # Static Methods

    # Class Methods

    # Public Methods

    def get_blacklisted_network_name(self, ip_string):
        """
        Gets the network name related to the network range that the IP
        address represented by ip_string resides in. If the IP address
        represented by ip_string does not reside within a network on
        the network blacklist, None will be returned.
        :param ip_string: The IP address in string format to retrieve
        the blacklisted network name for.
        :return: The name of the blacklisted network if the IP address
        represented by ip_string is blacklisted, otherwise None.
        """
        for cur_entry in self.blacklist_entries:
            if cur_entry.contains_ip(ip_string):
                return cur_entry.range_name
        return None

    def is_cidr_range_blacklisted(self, cidr_string):
        """
        Checks to see if the CIDR range represented by cidr_string resides on the IP address
        blacklist.
        :param cidr_string: A string containing a CIDR range to check for.
        :return: True if the CIDR range is on the blacklist, False otherwise.
        """
        for cur_entry in self.blacklist_entries:
            cidr_network = IPNetwork(cidr_string)
            if cur_entry.contains_cidr_range(cidr_string) or cur_entry.ip_range in cidr_network:
                return True
        return False

    def is_ip_blacklisted(self, ip_string):
        """
        Checks to see if the IP address represented by ip_string resides
        on the IP address blacklist.
        :param ip_string: The IP address in string format to test against.
        :return: True if the IP address is on the blacklist, False otherwise.
        """
        for cur_entry in self.blacklist_entries:
            if cur_entry.contains_ip(ip_string):
                return True
        return False

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def blacklist_entries(self):
        """
        Gets the list of IPBlacklistEntry objects as described by the
        IP blacklist file.
        :return: The list of IPBlacklistEntry objects as described by the
        IP blacklist file.
        """
        return self._blacklist_entries

    # Representation and Comparison


class IPBlacklistEntry(object):
    """
    A class representing a single entry found within the IP blacklist
    file.
    """
    
    # Class Members

    # Instantiation

    def __init__(self, blacklist_string):
        """
        Initialize a IPBlacklistEntry object based on the blacklist_string
        argument.
        :param blacklist_string: The string to build an IPBlacklistEntry object
         from.
        :return: None
        """
        self._ip_string = blacklist_string[:blacklist_string.find(",")].strip()
        self._range_name = blacklist_string[blacklist_string.find(",") + 1:].strip()
        if "-" in self._ip_string:
            range_start = self._ip_string[:self._ip_string.find("-")].strip()
            range_end = self._ip_string[self._ip_string.find("-") + 1:].strip()
            self._ip_range = IPRange(range_start, range_end)
        else:
            self._ip_range = IPNetwork(self._ip_string)

    # Static Methods

    # Class Methods

    # Public Methods

    def contains_cidr_range(self, cidr_string):
        """
        Check to see whether or not this blacklist entry contains the given network range.
        :param cidr_string: A string containing a CIDR range.
        :return: True if the CIDR range is contained by the network represented by this
        blacklist entry, False otherwise.
        """
        network = IPNetwork(cidr_string)
        return network in self.ip_range

    def contains_ip(self, ip_string):
        """
        Determines whether the IP address represented by ip_string is contained by
        the IP network that the given IPBlacklistEntry object represents.
        :param ip_string: The IP address to test against in string format.
        :return: True if the IP address is contained by the represented network,
        False otherwise.
        """
        ip = IPAddress(ip_string)
        return ip in self.ip_range

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def ip_range(self):
        """
        Get the netaddr object representing the range as described by the
        string used to initialize the IPBlacklistEntry object.
        :return: The netaddr object representing the range as described by the
        string used to initialize the IPBlacklistEntry object. This can be either
        a netaddr.IPRange or netaddr.IPNetwork.
        """
        return self._ip_range

    @property
    def ip_string(self):
        """
        Get the string that was used to initialize the IPBlacklistEntry object.
        :return: The string that was used to initialize the IPBlacklistEntry object.
        """
        return self._ip_string

    @property
    def range_name(self):
        """
        Get a string representation of the IP network that the IPBlacklistEntry
        represents.
        :return: A string representation of the IP network that the IPBlacklistEntry
        represents.
        """
        return self._range_name

    # Representation and Comparison
    
    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.ip_range)
