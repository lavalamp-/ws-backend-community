# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseOrganizationNetworkScanModel
from ..types import *


class ZmapScanResultModel(BaseOrganizationNetworkScanModel):
    """
    This is an Elasticsearch model for representing the results of a Zmap scan.
    """

    # Class Members

    start_time = DateElasticsearchType(
        help_text="The time at which the Zmap scan was started.",
    )
    end_time = DateElasticsearchType(
        help_text="The time at which the Zmap scan finished.",
    )
    cmd_line = KeywordElasticsearchType(
        help_text="The command that was invoked to start the Zmap scan.",
    )
    discovered_endpoints = KeywordElasticsearchType(
        help_text="The IP addresses that responded during the Zmap scan.",
    )
    live_service_count = IntElasticsearchType(
        help_text="The total number of IP addresses that responded during the Zmap scan.",
    )
    port = IntElasticsearchType(
        help_text="The port that was scanned for.",
    )
    protocol = KeywordElasticsearchType(
        help_text="The protocol that was used for the Zmap scan.",
    )
    scanned_networks = KeywordElasticsearchType(
        help_text="The network ranges that were scanned during the Zmap scan.",
    )
    scanned_networks_count = IntElasticsearchType(
        help_text="The number of network ranges that were scanned during the Zmap scan.",
    )

    # Instantiation

    def __init__(
            self,
            start_time=None,
            end_time=None,
            cmd_line=None,
            discovered_endpoints=[],
            port=None,
            protocol=None,
            scanned_networks=[],
            **kwargs
    ):
        super(ZmapScanResultModel, self).__init__(**kwargs)
        self.start_time = start_time
        self.end_time = end_time
        self.cmd_line = cmd_line
        self.discovered_endpoints = discovered_endpoints
        self.live_service_count = len(discovered_endpoints)
        self.port = port
        self.protocol = protocol
        self.scanned_networks = scanned_networks
        self.scanned_networks_count = len(scanned_networks)

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, DatetimeHelper
        to_populate.start_time = WsFaker.get_time_in_past()
        to_populate.end_time = DatetimeHelper.now()
        to_populate.cmd_line = WsFaker.get_command_line()
        discovered_endpoints = WsFaker.create_ip_addresses()
        to_populate.discovered_endpoints = discovered_endpoints
        to_populate.live_service_count = len(discovered_endpoints)
        to_populate.port = WsFaker.get_port()
        to_populate.protocol = WsFaker.get_network_protocol()
        scanned_networks = WsFaker.get_networks()
        to_populate.scanned_networks = scanned_networks
        to_populate.scanned_networks_count = len(scanned_networks)
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
