# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanModel
from ..types import *


class IpReverseHostnameModel(BaseIpAddressScanModel):
    """
    This is an Elasticsearch model class for containing information about the results of a reverse hostname
    lookup for an IP address.
    """

    # Class Members

    hostnames = KeywordElasticsearchType()

    # Instantiation

    def __init__(self, hostnames=None, **kwargs):
        super(IpReverseHostnameModel, self).__init__(**kwargs)
        self.hostnames = hostnames

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.hostnames = WsFaker.get_domain_names()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
