# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanModel
from ..types import *


class IpAddressReportModel(BaseIpAddressScanModel):
    """
    This is an Elasticsearch model class for containing aggregated data collected during a single
    IP address scan.
    """

    # Class Members

    open_tcp_ports = IntElasticsearchType()
    open_udp_ports = IntElasticsearchType()
    historic_domain_names = KeywordElasticsearchType()
    reverse_domain_names = KeywordElasticsearchType()
    geolocation_geohash = GeopointElasticsearchType()
    geolocation_latitude = DoubleElasticsearchType()
    geolocation_longitude = DoubleElasticsearchType()
    geolocation_region = KeywordElasticsearchType()
    geolocation_country_code = KeywordElasticsearchType()
    geolocation_postal_code = KeywordElasticsearchType()
    arin_whois_networks = WhoisNetworkElasticsearchType()
    unknown_domain_names = KeywordElasticsearchType()

    # Instantiation

    def __init__(
            self,
            open_tcp_ports=None,
            open_udp_ports=None,
            historic_domain_names=None,
            reverse_domain_names=None,
            geolocation_geohash=None,
            geolocation_latitude=None,
            geolocation_longitude=None,
            geolocation_region=None,
            geolocation_country_code=None,
            geolocation_postal_code=None,
            arin_whois_networks=None,
            unknown_domain_names=None,
            **kwargs
    ):
        super(IpAddressReportModel, self).__init__(**kwargs)
        self.open_tcp_ports = open_tcp_ports
        self.open_udp_ports = open_udp_ports
        self.historic_domain_names = historic_domain_names
        self.reverse_domain_names = reverse_domain_names
        self.geolocation_geohash = geolocation_geohash
        self.geolocation_latitude = geolocation_latitude
        self.geolocation_longitude = geolocation_longitude
        self.geolocation_region = geolocation_region
        self.geolocation_country_code = geolocation_country_code
        self.geolocation_postal_code = geolocation_postal_code
        self.arin_whois_networks = arin_whois_networks
        self.unknown_domain_names = unknown_domain_names

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.open_tcp_ports = WsFaker.get_ports()
        to_populate.open_udp_ports = WsFaker.get_ports()
        to_populate.historic_domain_names = WsFaker.get_domain_names()
        to_populate.reverse_domain_names = WsFaker.get_domain_names()
        to_populate.geolocation_geohash = WsFaker.get_geohash()
        to_populate.geolocation_latitude = WsFaker.get_latitude()
        to_populate.geolocation_longitude = WsFaker.get_longitude()
        to_populate.geolocation_region = WsFaker.get_region()
        to_populate.geolocation_country_code = WsFaker.get_country_code()
        to_populate.geolocation_postal_code = WsFaker.get_zip_code()
        to_populate.arin_whois_networks = WsFaker.get_whois_networks()
        to_populate.unknown_domain_names = WsFaker.get_domain_names()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
