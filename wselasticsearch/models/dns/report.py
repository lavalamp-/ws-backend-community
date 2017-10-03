# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseDomainNameScanModel
from ..types import *


class DomainNameReportModel(BaseDomainNameScanModel):
    """
    This is an Elasticsearch model class for containing aggregated and analyzed data about a
    domain name as gathered from a single domain name scan.
    """

    # Class Members

    domain_name = KeywordElasticsearchType(
        help_text="The domain name that this report is reflective of.",
    )
    resolutions = DomainResolutionElasticsearchType(
        help_text="The DNS resolutions that were discovered for the referenced domain name.",
    )
    has_resolutions = BooleanElasticsearchType(
        help_text="Whether or not the referenced domain had any successful resolutions.",
    )
    subdomains = SubdomainElasticsearchType(
        help_text="The subdomains that were discovered for the referenced parent domain.",
    )
    related_ips = DomainIpAddressElasticsearchType(
        help_text="IP addresses that were found related to this domain name.",
    )

    # Instantiation

    def __init__(
            self,
            domain_name=None,
            resolutions=None,
            has_resolutions=None,
            subdomains=None,
            related_ips=None,
            **kwargs
    ):
        super(DomainNameReportModel, self).__init__(**kwargs)
        self.domain_name = domain_name
        self.resolutions = resolutions
        self.has_resolutions = has_resolutions
        self.subdomains = subdomains
        self.related_ips = related_ips

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.domain_name = WsFaker.get_domain_name()
        to_populate.resolutions = WsFaker.get_domain_resolutions()
        to_populate.has_resolutions = RandomHelper.flip_coin()
        to_populate.subdomains = WsFaker.get_subdomains()
        to_populate.related_ips = WsFaker.get_domain_related_ips()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
