# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseComplexElasticsearchType
from .basic import *


class CidrRangeElasticsearchType(BaseComplexElasticsearchType):
    """
    This is an Elasticsearch type for representing a CIDR range.
    """

    def to_dict(self):
        return {
            "type": self.type,
            "properties": {
                "network_address": KeywordElasticsearchType().to_dict(),
                "mask_length": IntElasticsearchType().to_dict(),
            }
        }


class PortStatusElasticsearchType(BaseComplexElasticsearchType):
    """
    This is an Elasticsearch type for representing the status of a port.
    """

    def to_dict(self):
        return {
            "type": self.type,
            "properties": {
                "port_number": IntElasticsearchType().to_dict(),
                "port_protocol": KeywordElasticsearchType().to_dict(),
                "port_status": KeywordElasticsearchType().to_dict(),
            }
        }


class WhoisNetworkElasticsearchType(BaseComplexElasticsearchType):
    """
    This is an Elasticsearch type for representing data about a network retrieved via WHOIS.
    """

    def to_dict(self):
        return {
            "type": self.type,
            "properties": {
                "whois_org_name": KeywordElasticsearchType().to_dict(),
                "whois_org_handle": KeywordElasticsearchType().to_dict(),
                "whois_org_country_code": KeywordElasticsearchType().to_dict(),
                "whois_network_handle": KeywordElasticsearchType().to_dict(),
                "whois_network_name": KeywordElasticsearchType().to_dict(),
                "whois_network_range": CidrRangeElasticsearchType().to_dict()
            }
        }
