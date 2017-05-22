# -*- coding: utf-8 -*-
from __future__ import absolute_import

import requests
import Geohash

from .exception import BaseWsException
from .mixin import ElasticsearchableMixin
from .wscache import redis_cache


class GeolocationLookupFailedException(BaseWsException):
    """
    This is an exception for denoting that a geolocation lookup failed.
    """

    _message = "Geolocation lookup failed."


class IpGeolocator(object):
    """
    This is a class that contains methods for retrieving geolocation data about an IP address.
    """

    # Class Members

    _ip_api_url = "http://ip-api.com/json/"

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    @redis_cache
    def get_geolocation_for_ip_address_from_ipapi(self, ip_address):
        """
        Get geolocation data for the given IP address from IP API.
        :param ip_address: The IP address to retrieve geolocation data for.
        :return: An IpGeolocation object representing the contents of the response received from IP
        API.
        """
        url = self.__get_ip_api_url_for_address(ip_address)
        response = requests.get(url)
        return IpGeolocation.from_ip_api_response(response)

    def get_geolocations_for_ip_address(self, ip_address):
        """
        Get a list of geolocation data for the given IP address as retrieved from all of the Geolocation
        sources that this class supports.
        :param ip_address: The IP address to retrieve geolocation data about.
        :return: A list of IpGeolocation objects depicting geolocation data associated with the
        given IP address.
        """
        return [
            self.get_geolocation_for_ip_address_from_ipapi(ip_address),
        ]

    # Protected Methods

    # Private Methods

    def __get_ip_api_url_for_address(self, ip_address):
        """
        Get the URL that should be requested from IP API to retrieve geolocation data about the given
        IP address.
        :param ip_address: The IP address to create a URL for.
        :return: A string containing the URL that should be requested to retrieve geolocation data about
        the given IP address from IP API.
        """
        return "%s%s" % (self._ip_api_url, ip_address)

    # Properties

    # Representation and Comparison


class IpGeolocation(ElasticsearchableMixin):
    """
    This is a class for containing data about a geolocation associated with an IP address.
    """

    # Class Members

    # Instantiation

    def __init__(
            self,
            country=None,
            country_code=None,
            isp=None,
            latitude=None,
            longitude=None,
            region=None,
            region_name=None,
            postal_code=None,
            geo_source=None,
            ip_address=None,
    ):
        self.country = country
        self.country_code = country_code
        self.isp = isp
        self.latitude = latitude
        self.longitude = longitude
        self.region = region
        self.region_name = region_name
        self.postal_code = postal_code
        self.ip_address = ip_address
        self.geo_source = geo_source
        self.geohash = Geohash.encode(latitude, longitude)

    # Static Methods

    @staticmethod
    def from_ip_api_response(response):
        """
        Create and return an IpGeolocation object filled out via the contents of a response received by
        IP API.
        :param response: The response to process.
        :return: An IpGeolocation object representing the data found in the given response.
        """
        content = response.json()
        if content["status"] != "success":
            raise GeolocationLookupFailedException(
                "IP API lookup failed: %s"
                % (response.content,)
            )
        return IpGeolocation(
            country=content["country"],
            country_code=content["countryCode"],
            isp=content["isp"],
            latitude=content["lat"],
            longitude=content["lon"],
            region=content["region"],
            region_name=content["regionName"],
            postal_code=content["zip"],
            geo_source="ipapi",
            ip_address=content["query"],
        )

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import IpGeolocationModel
        return IpGeolocationModel

    # Public Methods

    # Protected Methods

    def _to_es_model(self):
        from wselasticsearch.models import IpGeolocationModel
        return IpGeolocationModel(
            geolocation=Geohash.encode(self.latitude, self.longitude),
            country_code=self.country_code,
            region=self.region,
            geo_source=self.geo_source,
            postal_code=self.postal_code,
            latitude=self.latitude,
            longitude=self.longitude,
        )

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s %s, %s>" % (
            self.__class__.__name__,
            self.ip_address,
            self.latitude,
            self.longitude,
        )
