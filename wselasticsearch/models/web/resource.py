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

    url_path = KeywordElasticsearchType(
        diff_key=True,
        help_text="The URL path to where this resource was served from.",
    )
    request_headers = KeywordKeyValueElasticsearchType(
        help_text="The HTTP request headers associated with the resource.",
    )
    request_method = KeywordElasticsearchType(
        diff_key=True,
        help_text="The HTTP request method that was used to retrieve this resource.",
    )
    response_headers = KeywordKeyValueElasticsearchType(
        help_text="The HTTP response headers associated with the resource.",
    )
    query_arguments = KeywordKeyValueElasticsearchType(
        diff_key=True,
        help_text="The query string arguments found within the request to the referenced web "
                  "resource.",
    )
    body_arguments = KeywordKeyValueElasticsearchType(
        diff_key=True,
        help_text="The body arguments found within the request to the referenced web resource.",
    )
    response_status = IntElasticsearchType(
        diffable=True,
        help_text="The HTTP status code returned by the request to the referenced web resource.",
    )
    content_type = KeywordElasticsearchType(
        diffable=True,
        help_text="The MIME content type associated with the resource.",
    )
    coalesced_content_type = KeywordElasticsearchType(
        help_text="The MIME content type associated with the resource coalesced into a set of "
                  "known and understood MIME types.",
    )
    content_length = IntElasticsearchType(
        help_text="The length in bytes of the referenced resource.",
    )
    content_md5_hash = KeywordElasticsearchType(
        help_text="The MD5 hash of the content of this resource.",
    )
    content_sha256_hash = KeywordElasticsearchType(
        help_text="The SHA256 hash of the content of this resource.",
    )
    header_redirect_location = KeywordElasticsearchType(
        help_text="The HTTP location header redirect location for this resource if such a "
                  "header was returned by requesting it.",
    )

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

    title = KeywordElasticsearchType(
        diffable=True,
        help_text="The title of the HTML content.",
    )
    tag_decomposition = TextElasticsearchType(
        diffable=True,
        help_text="A string depicting the sequence of HTML tags found in the response.",
    )
    total_tag_count = IntElasticsearchType(
        diffable=True,
        help_text="The total number of HTML tags found in this HTML resource.",
    )
    html_tags = KeywordIntKeyValueElasticsearchType(
        key_name="tag",
        value_name="count",
        help_text="Per-tag counts of the HTML tags found in this resource.",
    )
    internal_url_reference_count = IntElasticsearchType(
        diffable=True,
        help_text="The total number of URLs found in this resource pointing to resources "
                  "local to the referenced web service.",
    )
    external_url_reference_count = IntElasticsearchType(
        diffable=True,
        help_text="The total number of URLs found in this resource pointing to resources "
                  "remote to the referenced web service.",
    )
    forms = HtmlFormElasticsearchType(
        diffable=True,
        help_text="The forms found within this HTML resource.",
    )
    meta_refresh_location = KeywordElasticsearchType(
        diffable=True,
        help_text="The redirect location for a <meta> redirect tag in this HTML resource if such a tag exists.",
    )
    has_login_form = BooleanElasticsearchType(
        diffable=True,
        help_text="Whether or not a login form is present within this HTML resource.",
    )
    has_local_login_form = BooleanElasticsearchType(
        diffable=True,
        help_text="Whether or not a login form pointing to the serving web service is present within "
                  "this HTML resource.",
    )

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
