# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseNetworkServiceScanModel
from ..types import *


class VirtualHostModel(BaseNetworkServiceScanModel):
    """
    This is an Elasticsearch model class for maintaining data about virtual hosts discovered
    by Web Sight.
    """

    # Class Members

    hostname = KeywordElasticsearchType(
        help_text="The host name for the virtual host that was discovered.",
    )
    discovery_method = KeywordElasticsearchType(
        help_text="A string depicting how the referenced virtual host was discovered.",
    )

    # Instantiation

    def __init__(self, hostname=None, discovery_method=None, **kwargs):
        super(VirtualHostModel, self).__init__(**kwargs)
        self.hostname = hostname
        self.discovery_method = discovery_method

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.hostname = WsFaker.get_domain_name()
        to_populate.discovery_method = WsFaker.get_vhost_discovery_method()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s)>" % (self.__class__.__name__, self.hostname, self.discovery_method)

