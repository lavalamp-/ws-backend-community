# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..services.base import BaseNetworkServiceModel
from ..types import *


class BaseWebServiceModel(BaseNetworkServiceModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a single web service.
    """

    # Class Members

    web_service_uuid = KeywordElasticsearchType(
        help_text="The UUID of the web service that the data in this model is related to.",
    )
    web_service_host_name = KeywordElasticsearchType(
        help_text="The virtual host name of the web service that the data in this model is "
                  "related to.",
    )
    web_service_uses_ssl = BooleanElasticsearchType(
        help_text="Whether or not the referenced web service uses SSL.",
    )

    # Instantiation

    def __init__(self, web_service_uuid=None, web_service_host_name=None, web_service_uses_ssl=None, **kwargs):
        super(BaseWebServiceModel, self).__init__(**kwargs)
        self.web_service_uuid = web_service_uuid
        self.web_service_host_name = web_service_host_name
        self.web_service_uses_ssl = web_service_uses_ssl

    # Static Methods

    # Class Methods

    @classmethod
    def get_has_mapped_parent(cls):
        return True

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import WebService
        return WebService

    @classmethod
    def get_mapped_model_parent(cls):
        return "network_service"

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.web_service_uuid = WsFaker.create_uuid()
        to_populate.web_service_host_name = WsFaker.get_domain_name()
        to_populate.web_service_uses_ssl = RandomHelper.flip_coin()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.web_service_uuid = database_model.uuid
        to_populate.web_service_host_name = database_model.host_name
        to_populate.web_service_uses_ssl = database_model.ssl_enabled
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.web_service_uuid)


class BaseWebServiceScanModel(BaseWebServiceModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a single web service
    scan.
    """

    # Class Members

    web_service_scan_uuid = KeywordElasticsearchType(
        help_text="The UUID of the web service scan that the data in this model was "
                  "collected during.",
    )
    is_latest_scan = BooleanElasticsearchType(
        help_text="Whether or not the data in this model reflects the most recently collected data of "
                  "this format for the entity in question.",
    )

    # Instantiation

    def __init__(self, web_service_scan_uuid=None, is_latest_scan=False, **kwargs):
        super(BaseWebServiceScanModel, self).__init__(**kwargs)
        self.web_service_scan_uuid = web_service_scan_uuid
        self.is_latest_scan = is_latest_scan

    # Static Methods

    # Class Methods

    @classmethod
    def get_has_mapped_parent(cls):
        return True

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import WebServiceScan
        return WebServiceScan

    @classmethod
    def get_mapped_model_parent(cls):
        return "web_service"

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.web_service_scan_uuid = WsFaker.create_uuid()
        to_populate.is_latest_scan = RandomHelper.flip_coin()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.web_service_scan_uuid = database_model.uuid
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.web_service_scan_uuid)
