# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseDomainNameScanModel
from ..types import *


class SubdomainEnumerationModel(BaseDomainNameScanModel):
    """
    This is an Elasticsearch model for representing the results of a subdomain enumeration.
    """

    # Class Members

    enumeration_method = KeywordElasticsearchType()
    parent_domain = KeywordElasticsearchType()
    child_domains = KeywordElasticsearchType()

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
