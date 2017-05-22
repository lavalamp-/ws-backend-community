# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanModel
from ..types import *


class IpWhoisModel(BaseIpAddressScanModel):
    """
    This is an Elasticsearch model class for containing WHOIS data associated with an IP address.
    """

    # Class Members

    whois_org_name = KeywordElasticsearchType()
    whois_org_handle = KeywordElasticsearchType()
    whois_org_postal_code = KeywordElasticsearchType()
    whois_org_country_code = KeywordElasticsearchType()
    whois_org_street_address = KeywordElasticsearchType()
    whois_org_city = KeywordElasticsearchType()
    whois_org_state = KeywordElasticsearchType()
    whois_org_registration_date = DateElasticsearchType()
    whois_org_update_date = DateElasticsearchType()
    whois_network_handle = KeywordElasticsearchType()
    whois_network_name = KeywordElasticsearchType()
    whois_network_range = CidrRangeElasticsearchType()
    whois_network_registration_date = DateElasticsearchType()
    whois_network_update_date = DateElasticsearchType()
    whois_network_version = IntElasticsearchType()
    whois_data_source = KeywordElasticsearchType()

    # Instantiation

    def __init__(
            self,
            whois_org_name=None,
            whois_org_handle=None,
            whois_org_postal_code=None,
            whois_org_country_code=None,
            whois_org_street_address=None,
            whois_org_city=None,
            whois_org_state=None,
            whois_org_registration_date=None,
            whois_org_update_date=None,
            whois_network_handle=None,
            whois_network_name=None,
            whois_network_range=None,
            whois_network_registration_date=None,
            whois_network_update_date=None,
            whois_network_version=None,
            whois_data_source=None,
            **kwargs
    ):
        super(IpWhoisModel, self).__init__(**kwargs)
        self.whois_org_name = whois_org_name
        self.whois_org_handle = whois_org_handle
        self.whois_org_postal_code = whois_org_postal_code
        self.whois_org_country_code = whois_org_country_code
        self.whois_org_street_address = whois_org_street_address
        self.whois_org_city = whois_org_city
        self.whois_org_state = whois_org_state
        self.whois_org_registration_date = whois_org_registration_date
        self.whois_org_update_date = whois_org_update_date
        self.whois_network_handle = whois_network_handle
        self.whois_network_name = whois_network_name
        self.whois_network_range = whois_network_range
        self.whois_network_registration_date = whois_network_registration_date
        self.whois_network_update_date = whois_network_update_date
        self.whois_network_version = whois_network_version
        self.whois_data_source = whois_data_source

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.whois_org_name = WsFaker.get_word()
        to_populate.whois_org_handle = WsFaker.get_word()
        to_populate.whois_org_postal_code = WsFaker.get_zip_code()
        to_populate.whois_org_country_code = WsFaker.get_country_code()
        to_populate.whois_org_street_address = WsFaker.get_street_address()
        to_populate.whois_org_city = WsFaker.get_city()
        to_populate.whois_org_state = WsFaker.get_state_code()
        to_populate.whois_org_registration_date = WsFaker.get_time_in_past()
        to_populate.whois_org_update_date = WsFaker.get_time_in_past()
        to_populate.whois_network_handle = WsFaker.get_word()
        to_populate.whois_network_name = WsFaker.get_word()
        to_populate.whois_network_range = WsFaker.get_network_cidr_range()
        to_populate.whois_network_registration_date = WsFaker.get_time_in_past()
        to_populate.whois_network_update_date = WsFaker.get_time_in_past()
        to_populate.whois_network_version = WsFaker.get_random_int()
        to_populate.whois_data_source = WsFaker.get_word()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
