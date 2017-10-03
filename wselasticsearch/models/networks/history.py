# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanModel
from ..types import *


class IpDomainHistoryModel(BaseIpAddressScanModel):
    """
    This is an Elasticsearch model class for containing data about domain history for an IP
    address.
    """

    # Class Members

    domain_names = KeywordElasticsearchType(
        help_text="The domain names that the referenced IP address has been related to "
                  "historically.",
    )
    history_collection_method = KeywordElasticsearchType(
        help_text="A string depicting the method through which the IP address's domain history "
                  "was obtained.",
    )
    history_distance = IntElasticsearchType(
        help_text="How far back into the past domain history was collected for this IP address.",
    )

    # Instantiation

    def __init__(
            self,
            domain_names=None,
            history_collection_method=None,
            history_distance=None,
            **kwargs):
        super(IpDomainHistoryModel, self).__init__(**kwargs)
        self.domain_names = domain_names
        self.history_collection_method = history_collection_method
        self.history_distance = history_distance

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.domain_names = WsFaker.get_domain_names()
        to_populate.history_collection_method = WsFaker.get_domain_history_collection_method()
        to_populate.history_distance = WsFaker.get_random_int()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
