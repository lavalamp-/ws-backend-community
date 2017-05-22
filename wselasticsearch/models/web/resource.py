# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebServiceScanModel
from ..types import *


class BaseWebResourceModel(BaseWebServiceScanModel):
    """
    This is a base class for all Elasticsearch models that represent resources collected while
    investigating web services.
    """

    # Class Members

    url_path = KeywordElasticsearchType(diff_key=True)
    request_headers = KeywordKeyValueElasticsearchType()
    request_method = KeywordElasticsearchType(diff_key=True)
    response_headers = KeywordKeyValueElasticsearchType()
    query_arguments = KeywordKeyValueElasticsearchType(diff_key=True)
    body_arguments = KeywordKeyValueElasticsearchType(diff_key=True)
    response_status = IntElasticsearchType(diffable=True)
    content_type = KeywordElasticsearchType(diffable=True)
    coalesced_content_type = KeywordElasticsearchType()
    content_length = IntElasticsearchType()
    content_md5_hash = KeywordElasticsearchType()
    content_sha256_hash = KeywordElasticsearchType()
    header_redirect_location = KeywordElasticsearchType()

    # Instantiation

    def __init__(
            self,
            url_path=None,
            request_headers=None,
            request_method=None,
            response_headers=None,
            query_arguments=None,
            body_arguments=None,
            response_status=None,
            content_type=None,
            coalesced_content_type=None,
            content_length=None,
            content_md5_hash=None,
            content_sha256_hash=None,
            header_redirect_location=None,
            **kwargs
    ):
        super(BaseWebResourceModel, self).__init__(**kwargs)
        self.url_path = url_path
        self.request_headers = request_headers
        self.request_method = request_method
        self.response_headers = response_headers
        self.query_arguments = query_arguments
        self.body_arguments = body_arguments
        self.response_status = response_status
        self.content_type = content_type
        if coalesced_content_type is None:
            if content_type is not None:
                from lib.parsing import MimeWrapper
                from lib.parsing.wrappers.mime.base import InvalidMimeStringError
                try:
                    mime_wrapper = MimeWrapper(content_type)
                    self.coalesced_content_type = mime_wrapper.type
                except InvalidMimeStringError:
                    self.coalesced_content_type = "unknown"
            else:
                self.coalesced_content_type = "unknown"
        else:
            self.coalesced_content_type = coalesced_content_type
        self.content_length = content_length
        self.content_md5_hash = content_md5_hash
        self.content_sha256_hash = content_sha256_hash
        if header_redirect_location is None and response_headers is not None:
            for header in response_headers:
                if header["key"].lower() == "location":
                    header_redirect_location = header["value"]
        self.header_redirect_location = header_redirect_location

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.url_path = WsFaker.get_path()
        to_populate.request_headers = WsFaker.get_http_headers()
        to_populate.request_method = WsFaker.get_http_request_method()
        to_populate.response_headers = WsFaker.get_http_headers()
        to_populate.query_arguments = WsFaker.get_http_arguments()
        to_populate.body_arguments = WsFaker.get_http_arguments()
        to_populate.response_status = WsFaker.get_http_response_status()
        to_populate.content_type = WsFaker.get_mime_string()
        to_populate.coalesced_content_type = WsFaker.get_mime_string()
        to_populate.content_length = WsFaker.get_random_int()
        to_populate.content_md5_hash = WsFaker.get_md5_string()
        to_populate.content_sha256_hash = WsFaker.get_sha256_string()
        to_populate.header_redirect_location = WsFaker.get_url()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s %s %s %s>" % (
            self.__class__.__name__,
            self.url_path,
            self.content_length,
            self.content_type,
            self.content_md5_hash,
        )


class GenericWebResourceModel(BaseWebResourceModel):
    """
    This is a model class for representing a generic (ie: non-MIME-typed) resource retrieved
    via a web request.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class HtmlWebResourceModel(BaseWebResourceModel):
    """
    This is a model class for representing an HTML resource retrieved via a web request.
    """

    # Class Members

    title = KeywordElasticsearchType(diffable=True)
    tag_decomposition = TextElasticsearchType(diffable=True)
    total_tag_count = IntElasticsearchType(diffable=True)
    html_tags = KeywordIntKeyValueElasticsearchType(key_name="tag", value_name="count")
    internal_url_reference_count = IntElasticsearchType(diffable=True)
    external_url_reference_count = IntElasticsearchType(diffable=True)
    forms = HtmlFormElasticsearchType(diffable=True)
    meta_refresh_location = KeywordElasticsearchType(diffable=True)
    has_login_form = BooleanElasticsearchType(diffable=True)
    has_local_login_form = BooleanElasticsearchType(diffable=True)

    # Instantiation

    def __init__(
            self,
            title=None,
            tag_decomposition=None,
            total_tag_count=None,
            html_tags=None,
            internal_url_reference_count=None,
            external_url_reference_count=None,
            forms=None,
            meta_refresh_location=None,
            has_login_form=None,
            has_local_login_form=None,
            **kwargs
    ):
        super(HtmlWebResourceModel, self).__init__(**kwargs)
        self.title = title
        self.tag_decomposition = tag_decomposition
        self.total_tag_count = total_tag_count
        self.html_tags = html_tags
        self.internal_url_reference_count = internal_url_reference_count
        self.external_url_reference_count = external_url_reference_count
        self.forms = forms
        self.meta_refresh_location = meta_refresh_location
        self.has_login_form = has_login_form
        self.has_local_login_form = has_local_login_form

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.title = WsFaker.get_word()
        to_populate.tag_decomposition = WsFaker.get_word()
        to_populate.total_tag_count = WsFaker.get_random_int()
        to_populate.html_tags = WsFaker.get_html_tag_counts()
        to_populate.internal_url_reference_count = WsFaker.get_random_int()
        to_populate.external_url_reference_count = WsFaker.get_random_int()
        to_populate.forms = WsFaker.get_html_forms()
        to_populate.meta_refresh_location = WsFaker.get_url()
        to_populate.has_login_form = RandomHelper.flip_coin()
        to_populate.has_local_login_form = RandomHelper.flip_coin()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
