# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseDomainNameScanModel
from ..types import *
from lib import RegexLib


class DnsRecordModel(BaseDomainNameScanModel):
    """
    This is an Elasticsearch model for representing the results of a DNS record lookup.
    """

    # Class Members

    record_type = KeywordElasticsearchType(
        help_text="The DNS record type that was queried.",
    )
    record_content = KeywordElasticsearchType(
        help_text="The contents of the queried DNS record.",
    )
    contains_ip_address = BooleanElasticsearchType(
        help_text="Whether or not the contents of this record contain an IP address.",
    )
    ip_address_uuid = KeywordElasticsearchType(
        help_text="The UUID of the IP address that the record_content point to, if such an "
                  "IP address exists within Web Sight.",
    )

    # Instantiation

    def __init__(
            self,
            record_type=None,
            record_content=None,
            ip_address_uuid=None,
            contains_ip_address=None,
            **kwargs
    ):
        super(DnsRecordModel, self).__init__(**kwargs)
        self.record_type = record_type
        self.record_content = record_content
        self.ip_address_uuid = ip_address_uuid
        if contains_ip_address is None:
            contains_ip_address = bool(RegexLib.ipv4_address_regex.match(record_content))
        self.contains_ip_address = contains_ip_address

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        contains_ip = RandomHelper.flip_coin()
        to_populate.record_type = WsFaker.get_dns_record_type()
        to_populate.record_content = WsFaker.get_dns_record_content()
        to_populate.contains_ip_address = contains_ip
        to_populate.ip_address_uuid = WsFaker.create_uuid() if contains_ip else None
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
