# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseScanElasticsearchModel
from ..services.base import BaseNetworkServiceModel
from .mixin import WebRequestMixin, ResourceInfoMixin, UrlMixin
from ..mixin import ServiceMixin
from ..types import *


class BaseWebServiceModel(BaseNetworkServiceModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a single web service.
    """

    # Class Members

    web_service_uuid = KeywordElasticsearchType()
    web_service_host_name = KeywordElasticsearchType()
    web_service_uses_ssl = BooleanElasticsearchType()

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

    web_service_scan_uuid = KeywordElasticsearchType()
    is_latest_scan = BooleanElasticsearchType()

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


class BaseWebServiceUrlModel(BaseWebServiceModel, UrlMixin):
    """
    This is a base Elasticsearch model for representing data that is tied to a URL for a web service.
    """

    # Class Members

    # Instantiation

    def __init__(self, url=None, **kwargs):
        super(BaseWebServiceUrlModel, self).__init__(**kwargs)
        self.url = url

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.url = WsFaker.get_url()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s)>" % (self.__class__.__name__, self.web_service_uuid, self.url)


class BaseWebModel(BaseScanElasticsearchModel, ServiceMixin):
    """
    This is a base class for all Elasticsearch models that are created while investigating
    web services.
    """

    # Class Members

    # Instantiation

    def __init__(self, service_uuid=None, **kwargs):
        super(BaseWebModel, self).__init__(**kwargs)
        self.service_uuid = service_uuid

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseWebUrlModel(BaseWebModel, UrlMixin):
    """
    This is a base class for all Elasticsearch models that are created while investigating web
    services and are related to a specific URL.
    """

    # Class Members

    # Instantiation

    def __init__(
            self,
            url=None,
            **kwargs
    ):
        super(BaseWebUrlModel, self).__init__(**kwargs)
        self.url = url

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseWebResourceModel(BaseWebModel, WebRequestMixin, ResourceInfoMixin):
    """
    This is a base class for all Elasticsearch models that represent resources collected while
    investigating web services.
    """

    # Class Members

    content = TextElasticsearchType()

    # Instantiation

    def __init__(
            self,
            content_type=None,
            content_length=None,
            content_hash=None,
            content_secondary_hash=None,
            content=None,
            url=None,
            request_headers=None,
            request_method=None,
            query_arguments=None,
            body_arguments=None,
            response_status=None,
            **kwargs
    ):
        super(BaseWebResourceModel, self).__init__(**kwargs)
        self.content_type = content_type
        self.content_length = content_length
        self.content_hash = content_hash
        self.content_secondary_hash = content_secondary_hash
        self.content = content
        self.url = url
        self.request_headers = self._tuples_to_key_value_dicts(request_headers)
        self.request_method = request_method
        self.query_arguments = self._tuples_to_key_value_dicts(query_arguments)
        self.body_arguments = self._tuples_to_key_value_dicts(body_arguments)
        self.response_status = response_status

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s %s %s %s>" % (
            self.__class__.__name__,
            self.url,
            self.content_length,
            self.content_type,
            self.content_hash,
        )
