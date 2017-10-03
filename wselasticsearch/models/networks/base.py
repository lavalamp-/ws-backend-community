# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..organizations.base import BaseOrganizationModel
from ..types import *


class BaseNetworkModel(BaseOrganizationModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a single network.
    """

    # Class Members

    network_uuid = KeywordElasticsearchType(
        help_text="The UUID of the network range that the data in this model is related to.",
    )
    network_address = TextElasticsearchType(
        help_text="The base network address for the network range that the data in this model is "
                  "related to.",
    )
    network_name = KeywordElasticsearchType(
        help_text="The name that was given to the network range that the data in this model is related "
                  "to.",
    )
    network_mask_length = IntElasticsearchType(
        help_text="The length of the CIDR mask for the network range that the data in this model is "
                  "related to.",
    )
    network_cidr_range = KeywordElasticsearchType(
        help_text="The full network CIDR range for the network range that the data in this model "
                  "is related to.",
    )
    network_added_by = KeywordElasticsearchType(
        help_text="A string depicting the way that the referenced network range was added to the "
                  "Web Sight back-end data store.",
    )

    # Instantiation

    def __init__(
            self,
            network_uuid=None,
            network_address=None,
            network_name=None,
            network_mask_length=None,
            network_cidr_range=None,
            network_added_by=None,
            **kwargs
    ):
        super(BaseNetworkModel, self).__init__(**kwargs)
        self.network_uuid = network_uuid
        self.network_address = network_address
        self.network_name = network_name
        self.network_mask_length = network_mask_length
        self.network_cidr_range = network_cidr_range
        self.network_added_by = network_added_by

    # Static Methods

    # Class Methods

    @classmethod
    def get_has_mapped_parent(cls):
        return True

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import Network
        return Network

    @classmethod
    def get_mapped_model_parent(cls):
        return "organization"

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.network_uuid = WsFaker.create_uuid()
        to_populate.network_address = WsFaker.get_ipv4_address()
        to_populate.network_name = WsFaker.get_network_name()
        to_populate.network_mask_length = WsFaker.get_random_int(minimum=1, maximum=32)
        to_populate.network_cidr_range = "%s/%s" % (to_populate.network_address, to_populate.network_mask_length)
        to_populate.network_added_by = WsFaker.get_word()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.network_uuid = database_model.uuid
        to_populate.network_address = database_model.address
        to_populate.network_name = database_model.name
        to_populate.network_mask_length = database_model.mask_length
        to_populate.network_cidr_range = database_model.cidr_range
        to_populate.network_added_by = database_model.added_by
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.network_uuid)


class BaseIpAddressModel(BaseNetworkModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a single IP address.
    """

    # Class Members

    ip_address_uuid = KeywordElasticsearchType(
        help_text="The UUID of the IP address that the data in this model is related to.",
    )
    ip_address = KeywordElasticsearchType(
        help_text="The IP address that the data in this model is related to.",
    )
    ip_address_type = KeywordElasticsearchType(
        help_text="A string depicting the type of IP address that this model is related to "
                  "(IPv4 or IPv6).",
    )

    # Instantiation

    def __init__(self, ip_address_uuid=None, ip_address=None, ip_address_type=None, **kwargs):
        super(BaseIpAddressModel, self).__init__(**kwargs)
        self.ip_address_uuid = ip_address_uuid
        self.ip_address = ip_address
        self.ip_address_type = ip_address_type

    # Static Methods

    # Class Methods

    @classmethod
    def get_has_mapped_parent(cls):
        return True

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import IpAddress
        return IpAddress

    @classmethod
    def get_mapped_model_parent(cls):
        return "network"

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.ip_address_uuid = WsFaker.create_uuid()
        to_populate.ip_address = WsFaker.get_ipv4_address()
        to_populate.ip_address_type = WsFaker.get_ip_address_type()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.ip_address_uuid = database_model.uuid
        to_populate.ip_address = database_model.address
        to_populate.ip_address_type = database_model.address_type
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.ip_address_uuid)


class BaseIpAddressScanModel(BaseIpAddressModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a given IP address scan.
    """

    # Class Members

    ip_address_scan_uuid = KeywordElasticsearchType(
        help_text="The UUID of the IP address scan that the data in this model was collected during.",
    )
    is_latest_scan = BooleanElasticsearchType(
        help_text="Whether or not the data in this model reflects the most recently collected data of "
                  "this format for the entity in question.",
    )

    # Instantiation

    def __init__(self, ip_address_scan_uuid=None, is_latest_scan=None, **kwargs):
        super(BaseIpAddressScanModel, self).__init__(**kwargs)
        self.ip_address_scan_uuid = ip_address_scan_uuid
        self.is_latest_scan = is_latest_scan

    # Static Methods

    # Class Methods

    @classmethod
    def get_has_mapped_parent(cls):
        return True

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import IpAddressScan
        return IpAddressScan

    @classmethod
    def get_mapped_model_parent(cls):
        return "ip_address"

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.ip_address_scan_uuid = WsFaker.create_uuid()
        to_populate.is_latest_scan = RandomHelper.flip_coin()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.ip_address_scan_uuid = database_model.uuid
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.ip_address_scan_uuid)


