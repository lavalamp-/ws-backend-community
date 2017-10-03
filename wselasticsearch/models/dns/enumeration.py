# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseDomainNameScanModel
from ..types import *


class SubdomainEnumerationModel(BaseDomainNameScanModel):
    """
    This is an Elasticsearch model for representing the results of a subdomain enumeration.
    """

    # Class Members

    enumeration_method = KeywordElasticsearchType(
        help_text="A string depicting how the domains within this model were discovered.",
    )
    parent_domain = KeywordElasticsearchType(
        help_text="The parent domain name that subdomain enumeration was run for.",
    )
    child_domains = KeywordElasticsearchType(
        help_text="The child domain names that were discovered through the referenced subdomain "
                  "enumeration process.",
    )

    # Instantiation

    def __init__(self, enumeration_method=None, child_domains=None, parent_domain=None, **kwargs):
        super(SubdomainEnumerationModel, self).__init__(**kwargs)
        self.enumeration_method = enumeration_method
        self.child_domains = child_domains
        self.parent_domain = parent_domain

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.enumeration_method = WsFaker.get_word()
        to_populate.child_domains = WsFaker.get_domain_names()
        to_populate.parent_domain = WsFaker.get_domain_name()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
