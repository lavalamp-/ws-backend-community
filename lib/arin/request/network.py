# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseManyArinRequest, BaseSingleArinRequest


class NetworkArinRequest(BaseSingleArinRequest):
    """
    This is a request class for requesting information about a single network.
    """

    @classmethod
    def get_response_class(cls):
        from ..response import NetworkArinResponse
        return NetworkArinResponse

    @classmethod
    def get_url_path(cls):
        return "net"


class NetworksArinRequest(BaseManyArinRequest):
    """
    This is a request class for requesting information about multiple networks.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_networks_by_ip_address(cls, ip_address, *args, **kwargs):
        """
        Perform a search for all networks that contain the given IP address.
        :param ip_address: The IP address to search for.
        :param args: Positional arguments to pass to requests.get.
        :param kwargs: Keyword arguments to pass to requests.get.
        :return: An ARIN response object wrapping the response returned by the ARIN WHOIS
        RWS API.
        """
        return cls.search_by_key(key="q", value=ip_address, wild_before=False, wild_after=False, *args, **kwargs)

    @classmethod
    def get_response_class(cls):
        from ..response import NetworksArinResponse
        return NetworksArinResponse

    @classmethod
    def get_url_path(cls):
        return "nets"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
