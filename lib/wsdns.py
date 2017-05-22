# -*- coding: utf-8 -*-
from __future__ import absolute_import

from uuid import uuid4
from subprocess import Popen
import billiard

from .config import ConfigManager
from .singleton import Singleton
from .exception import BaseWsException

config = ConfigManager.instance()


class ResolutionAlreadyExistsError(BaseWsException):
    """
    This is an exception for denoting that a resolution already exists within the DnsResolutionHelper.
    """

    _message = "Resolution already exists."


class NoResolutionFoundError(BaseWsException):
    """
    This is an exception for denoting that a domain name is not currently managed by the helper.
    """

    _message = "Unknown domain name."


@Singleton
class DnsResolutionHelper(object):
    """
    This is a class that enables Web Sight code to modify what various domain names resolve to.
    """

    # Class Members

    _hosts_tag = "WEB SIGHT DNS"

    # Instantiation

    def __init__(self):
        self._resolution_map = {}
        self._tags_map = {}

    # Static Methods

    # Class Methods

    # Public Methods

    def add_resolution(self, domain_name=None, ip_address=None):
        """
        Add a resolution to the list of resolutions managed by this helper class that resolves
        the given domain name to the given IP address.
        :param domain_name: The domain name to resolve.
        :param ip_address: The IP address it should resolve to.
        :return: None
        """
        if domain_name in self.resolution_map:
            raise ResolutionAlreadyExistsError(
                "%s already is configured to resolve to %s."
                % (domain_name, self.resolution_map[domain_name])
            )
        hosts_entry, unique_id = self.__get_hosts_entry_for_resolution(domain_name=domain_name, ip_address=ip_address)
        Popen(["echo \"%s\" >> %s" % (hosts_entry, config.dns_hosts_file_location)], shell=True)
        self._resolution_map[domain_name] = ip_address
        self._tags_map[domain_name] = unique_id

    def remove_resolution(self, domain_name):
        """
        Remove the resolution associated with the given domain name from the hosts file.
        :param domain_name: The domain name to remove.
        :return: None
        """
        if domain_name not in self.resolution_map:
            raise NoResolutionFoundError(
                "Domain %s was not found in the map of existing resolutions."
                % (domain_name,)
            )
        removal_command = self.__get_removal_command(self._tags_map[domain_name])
        Popen([removal_command], shell=True)
        del self._resolution_map[domain_name]
        del self._tags_map[domain_name]

    # Protected Methods

    # Private Methods

    def __get_hosts_entry_for_resolution(self, domain_name=None, ip_address=None):
        """
        Get a string representing the content that should be placed into the hosts files to resolve
        the given domain name to the given IP address.
        :param domain_name: The domain name.
        :param ip_address: The IP address.
        :return: A tuple containing (1) the string to add to /etc/hosts and (2) the unique identifier
        associated with the entry.
        """
        unique_id = str(uuid4())
        return "%s %s # %s %s" % (ip_address, domain_name, self._hosts_tag, unique_id), unique_id

    def __get_removal_command(self, unique_id):
        """
        Get a string representing the shell command to be run that removes the entry associated with
        the given unique ID from the hosts file.
        :param unique_id: The unique ID to remove from the hosts file.
        :return: The command to run to remove the given unique ID from the hosts file.
        """
        temp_file = str(uuid4())
        return "cat %s | grep -v %s > /tmp/%s; cat /tmp/%s > %s; rm /tmp/%s" % (
            config.dns_hosts_file_location,
            unique_id,
            temp_file,
            temp_file,
            config.dns_hosts_file_location,
            temp_file,
        )

    # Properties

    @property
    def resolution_map(self):
        """
        Get a dictionary that maps domain names to the IP addresses they are configured to resolve to.
        :return: a dictionary that maps domain names to the IP addresses they are configured to resolve to.
        """
        return self._resolution_map

    # Representation and Comparison
