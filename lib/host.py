# -*- coding: utf-8 -*-
from __future__ import absolute_import

import netifaces
import ssl


class HostHelper(object):
    """
    This class contains helper methods for querying the configuration / setup / capabilities of
    the host where the code is running.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def get_all_network_interfaces():
        """
        Get a list of strings describing the network interface names associated with the host computer.
        :return: A list of strings describing the network interface names associated with the host computer.
        """
        return netifaces.interfaces()

    @staticmethod
    def get_available_ssl_version_names():
        """
        Get a list containing strings representing the SSL protocols this host supports.
        :return: A list containing strings representing the SSL protocols this host supports.
        """
        return ssl._PROTOCOL_NAMES.values()

    @staticmethod
    def get_available_ssl_versions():
        """
        Get a list containing the SSL versions available to this host.
        :return:
        """
        return ssl._PROTOCOL_NAMES.keys()

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
