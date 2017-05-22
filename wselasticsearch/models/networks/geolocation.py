# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseIpAddressScanModel
from ..types import *


class IpGeolocationModel(BaseIpAddressScanModel):
    """
    This is an Elasticsearch model class for containing information about geolocation data associated with
    an IP address.
    """

    # Class Members

    geolocation = GeopointElasticsearchType()
    country_code = KeywordElasticsearchType()
    region = KeywordElasticsearchType()
    geo_source = KeywordElasticsearchType()
    postal_code = KeywordElasticsearchType()
    latitude = DoubleElasticsearchType()
    longitude = DoubleElasticsearchType()

    # Instantiation

    def __init__(
            self,
            geolocation=None,
            country_code=None,
            region=None,
            geo_source=None,
            postal_code=None,
            latitude=None,
            longitude=None,
            **kwargs
    ):
        super(IpGeolocationModel, self).__init__(**kwargs)
        self.geolocation = geolocation
        self.country_code = country_code
        self.region = region
        self.geo_source = geo_source
        self.postal_code = postal_code
        self.latitude = latitude
        self.longitude = longitude

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.geolocation = WsFaker.get_geohash()
        to_populate.country_code = WsFaker.get_country_code()
        to_populate.region = WsFaker.get_region()
        to_populate.geo_source = WsFaker.get_geo_source()
        to_populate.postal_code = WsFaker.get_zip_code()
        to_populate.latitude = WsFaker.get_latitude()
        to_populate.longitude = WsFaker.get_longitude()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
