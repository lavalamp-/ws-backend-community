# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseComplexElasticsearchType
from .basic import *


class DomainIpAddressElasticsearchType(BaseComplexElasticsearchType):
    """
    This is an Elasticsearch type for representing an IP address that is related to a domain name.
    """

    def to_dict(self):
        return {
            "type": self.type,
            "properties": {
                "ip_address": KeywordElasticsearchType().to_dict(),
                "ip_address_uuid": KeywordElasticsearchType().to_dict(),
            }
        }


class SubdomainElasticsearchType(BaseComplexElasticsearchType):
    """
    This is an Elasticsearch type for representing a subdomain that is related to a domain name.
    """

    def to_dict(self):
        return {
            "type": self.type,
            "properties": {
                "subdomain": KeywordElasticsearchType().to_dict(),
                "domain_uuid": KeywordElasticsearchType().to_dict(),
            }
        }


class DomainResolutionElasticsearchType(BaseComplexElasticsearchType):
    """
    This is an Elasticsearch type for representing the results of a domain resolution.
    """

    def to_dict(self):
        return {
            "type": self.type,
            "properties": {
                "record_type": KeywordElasticsearchType().to_dict(),
                "record_contents": KeywordElasticsearchType().to_dict(),
            }
        }
