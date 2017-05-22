# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseScanElasticsearchModel
from .types import *


class ZmapResultModel(BaseScanElasticsearchModel):
    """
    An Elasticsearch model for representing the results of a Zmap scan.
    """

    # Class Members

    cmd_line = TextElasticsearchType()
    end_time = DateElasticsearchType()
    discovered_endpoints = TextElasticsearchType()
    live_service_count = IntElasticsearchType()
    port = IntElasticsearchType()
    scanned_networks = KeywordElasticsearchType()
    scanned_networks_count = IntElasticsearchType()
    start_time = DateElasticsearchType()

    # Instantiation

    def __init__(
            self,
            start_time=None,
            end_time=None,
            port=None,
            discovered_endpoints=None,
            cmd_line=None,
            scanned_networks=None,
            **kwargs
    ):
        super(ZmapResultModel, self).__init__(**kwargs)
        self.start_time = start_time
        self.end_time = end_time
        self.port = port
        self.discovered_endpoints = discovered_endpoints
        self.cmd_line = cmd_line
        self.scanned_networks = scanned_networks
        self.live_service_count = len(self.discovered_endpoints)
        self.scanned_networks_count = len(self.scanned_networks)

    # Static Methods

    # Class Methods

    @classmethod
    def create_dummy(cls):
        from lib import DatetimeHelper, WsFaker
        return ZmapResultModel(
            start_time=DatetimeHelper.minutes_ago(5),
            end_time=DatetimeHelper.now(),
            port=WsFaker.get_port(),
            discovered_endpoints=WsFaker.create_ip_addresses(),
            cmd_line="zmap -B 10M -f \"saddr,daddr\" -w /tmp/white -o /tmp/zmap_output -p 80 -i en0",
            scanned_networks=WsFaker.create_class_c_networks(),
            org_uuid=WsFaker.create_uuid(),
        )

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s)>" % (self.__class__.__name__, self.cmd_line, self.end_time)

