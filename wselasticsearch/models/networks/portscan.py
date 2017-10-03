# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanModel
from ..types import *


class IpPortScanModel(BaseIpAddressScanModel):
    """
    This is an Elasticsearch model class for containing data about the results of a port scan of
    an IP address.
    """

    # Class Members

    port_results = PortStatusElasticsearchType(
        help_text="The per-port results of the port scans for the referenced IP address.",
    )
    port_scan_method = KeywordElasticsearchType(
        help_text="A string depicting the method via which the referenced port scan was performed.",
    )
    scan_start_time = DateElasticsearchType(
        help_text="The time at which the referenced port scan was started.",
    )
    scan_end_time = DateElasticsearchType(
        help_text="The time at which the referenced port scan ended.",
    )

    # Instantiation

    def __init__(
            self,
            port_results=None,
            port_scan_method=None,
            scan_start_time=None,
            scan_end_time=None,
            **kwargs
    ):
        super(IpPortScanModel, self).__init__(**kwargs)
        self.port_results = port_results
        self.port_scan_method = port_scan_method
        self.scan_start_time = scan_start_time
        self.scan_end_time = scan_end_time

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.port_results = WsFaker.get_port_statuses()
        to_populate.port_scan_method = WsFaker.get_port_scan_method()
        to_populate.scan_start_time = WsFaker.get_time_in_past()
        to_populate.scan_end_time = WsFaker.get_time_in_past()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
