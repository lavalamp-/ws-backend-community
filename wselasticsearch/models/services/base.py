# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..networks.base import BaseIpAddressModel
from ..types import *


class BaseNetworkServiceModel(BaseIpAddressModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a single network service.
    """

    # Class Members

    network_service_uuid = KeywordElasticsearchType(
        help_text="The UUID of the network service that the data in this model is related to.",
    )
    network_service_port = IntElasticsearchType(
        help_text="The port of the network service that the data in this model is related to.",
    )
    network_service_protocol = KeywordElasticsearchType(
        help_text="The protocol of the network service that the data in this model is related to.",
    )
    network_service_discovered_by = KeywordElasticsearchType(
        help_text="A string depicting how the referenced network service was discovered by Web Sight.",
    )

    # Instantiation

    def __init__(
            self,
            network_service_uuid=None,
            network_service_port=None,
            network_service_protocol=None,
            network_service_discovered_by=None,
            **kwargs
    ):
        super(BaseNetworkServiceModel, self).__init__(**kwargs)
        self.network_service_port = network_service_port
        self.network_service_protocol = network_service_protocol
        self.network_service_uuid = network_service_uuid
        self.network_service_discovered_by = network_service_discovered_by

    # Static Methods

    # Class Methods

    @classmethod
    def get_has_mapped_parent(cls):
        return True

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import NetworkService
        return NetworkService

    @classmethod
    def get_mapped_model_parent(cls):
        return "ip_address"

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.network_service_port = WsFaker.get_port()
        to_populate.network_service_protocol = WsFaker.get_network_protocol()
        to_populate.network_service_uuid = WsFaker.create_uuid()
        to_populate.network_service_discovered_by = WsFaker.get_network_service_discovery_method()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.network_service_uuid = database_model.uuid
        to_populate.network_service_port = database_model.port
        to_populate.network_service_protocol = database_model.protocol
        to_populate.network_service_discovered_by = database_model.discovered_by
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.network_service_uuid)


class BaseNetworkServiceScanModel(BaseNetworkServiceModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a single network service
    scan.
    """

    # Class Members

    network_service_scan_uuid = KeywordElasticsearchType(
        help_text="The UUID of the network service scan that the data in this model was collected "
                  "during.",
    )
    is_latest_scan = BooleanElasticsearchType(
        help_text="Whether or not the data in this model reflects the most recently collected data of "
                  "this format for the entity in question.",
    )

    # Instantiation

    def __init__(self, network_service_scan_uuid=None, is_latest_scan=None, **kwargs):
        super(BaseNetworkServiceScanModel, self).__init__(**kwargs)
        self.network_service_scan_uuid = network_service_scan_uuid
        self.is_latest_scan = is_latest_scan

    # Static Methods

    # Class Methods

    @classmethod
    def get_has_mapped_parent(cls):
        return True

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import NetworkServiceScan
        return NetworkServiceScan

    @classmethod
    def get_mapped_model_parent(cls):
        return "network_service"

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.network_service_scan_uuid = WsFaker.create_uuid()
        to_populate.is_latest_scan = RandomHelper.flip_coin()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.network_service_scan_uuid = database_model.uuid
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.network_service_scan_uuid)
