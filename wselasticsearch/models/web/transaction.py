# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebServiceScanModel
from .mixin import WebRequestMixin, ResourceInfoMixin
from ..types import *


class HttpTransactionModel(BaseWebServiceScanModel, WebRequestMixin, ResourceInfoMixin):
    """
    Documentation for HttpTransactionModel.
    """

    # Class Members

    response_headers = KeywordKeyValueElasticsearchType(
        help_text="The HTTP response headers associated with this transaction.",
    )

    # Instantiation

    def __init__(
            self,
            response_headers=None,
            content_type=None,
            content_length=None,
            content_hash=None,
            content_secondary_hash=None,
            request_headers=None,
            request_method=None,
            query_arguments=None,
            body_arguments=None,
            response_status=None,
            url=None,
            **kwargs
    ):
        super(HttpTransactionModel, self).__init__(**kwargs)
        self.response_headers = self._tuples_to_key_value_dicts(response_headers)
        self.content_type = content_type
        self.content_length = content_length
        self.content_hash = content_hash
        self.content_secondary_hash = content_secondary_hash
        self.request_headers = self._tuples_to_key_value_dicts(request_headers)
        self.request_method = request_method
        self.query_arguments = self._tuples_to_key_value_dicts(query_arguments)
        self.body_arguments = self._tuples_to_key_value_dicts(body_arguments)
        self.response_status = response_status
        self.url = url

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.response_headers = WsFaker.get_http_headers()
        to_populate.content_type = WsFaker.get_mime_string()
        to_populate.content_length = WsFaker.get_random_int()
        to_populate.content_hash = WsFaker.get_sha256_string()
        to_populate.content_secondary_hash = WsFaker.get_sha256_string()
        to_populate.request_headers = WsFaker.get_http_headers()
        to_populate.request_method = WsFaker.get_http_request_method()
        to_populate.query_arguments = WsFaker.get_http_arguments()
        to_populate.body_arguments = WsFaker.get_http_arguments()
        to_populate.response_status = WsFaker.get_http_response_status()
        to_populate.url = WsFaker.get_url()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s %s %s %s>" % (
            self.__class__.__name__,
            self.url,
            self.response_status,
            self.content_type,
            self.content_hash,
        )

