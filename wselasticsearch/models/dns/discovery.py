# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseDomainNameScanModel
from ..types import *


class DiscoveredDomainNameModel(BaseDomainNameScanModel):
    """
    This is an Elasticsearch model for representing a domain name that was discovered during a domain
    name scan.
    """

    # Class Members

    discovered_domain_name = KeywordElasticsearchType()
    discovery_method = KeywordElasticsearchType()

    # Instantiation

    def __init__(self, discovered_domain_name=None, discovery_method=None, **kwargs):
        super(DiscoveredDomainNameModel, self).__init__(**kwargs)
        self.discovery_method = discovery_method
        self.discovered_domain_name = discovered_domain_name

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.discovery_method = WsFaker.get_domain_discovery_method()
        to_populate.discovered_domain_name = WsFaker.get_domain_name()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

