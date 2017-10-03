# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanModel
from ..types import *


class IpWhoisModel(BaseIpAddressScanModel):
    """
    This is an Elasticsearch model class for containing WHOIS data associated with an IP address.
    """

    # Class Members

    whois_org_name = KeywordElasticsearchType(
        help_text="The name of the organization who owns the WHOIS record for the IP address.",
    )
    whois_org_handle = KeywordElasticsearchType(
        help_text="The handle of the organization who owns the WHOIS record for the IP address.",
    )
    whois_org_postal_code = KeywordElasticsearchType(
        help_text="The postal code of the organization who owns the WHOIS record for the "
                  "IP address.",
    )
    whois_org_country_code = KeywordElasticsearchType(
        help_text="The country code of the organization who owns the WHOIS record for the IP "
                  "address.",
    )
    whois_org_street_address = KeywordElasticsearchType(
        help_text="The street address of the organization who owns the WHOIS record for "
                  "the IP address.",
    )
    whois_org_city = KeywordElasticsearchType(
        help_text="The city of the organization who owns the WHOIS record for the IP address.",
    )
    whois_org_state = KeywordElasticsearchType(
        help_text="The state of the organization who owns the WHOIS record for the IP address.",
    )
    whois_org_registration_date = DateElasticsearchType(
        help_text="The date when the organization who owns the WHOIS record for the IP address "
                  "registered their WHOIS allocation.",
    )
    whois_org_update_date = DateElasticsearchType(
        help_text="The last time that the organization that owns the referenced WHOIS record updated "
                  "their information.",
    )
    whois_network_handle = KeywordElasticsearchType(
        help_text="A string reflecting the handle of the network that the IP address is contained "
                  "within in its WHOIS record.",
    )
    whois_network_name = KeywordElasticsearchType(
        help_text="A string reflecting the name of the network that the IP address is contained "
                  "within in its WHOIS record.",
    )
    whois_network_range = CidrRangeElasticsearchType(
        help_text="The CIDR range of the network that the IP address is contained within in "
                  "its WHOIS record.",
    )
    whois_network_registration_date = DateElasticsearchType(
        help_text="The date at which the network this IP address's WHOIS record was registered.",
    )
    whois_network_update_date = DateElasticsearchType(
        help_text="The last time when the network that this IP address's WHOIS record was updated.",
    )
    whois_network_version = IntElasticsearchType(
        help_text="A string depicting the version of the network data that the IP address's WHOIS record "
                  "reflects.",
    )
    whois_data_source = KeywordElasticsearchType(
        help_text="A string depicting the source of the WHOIS data that this record was populated via.",
    )

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
