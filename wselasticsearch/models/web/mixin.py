# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..types import *


class UrlMixin(object):
    """
    This is a mixin class for Elasticsearch models that are related to a single URL.
    """

    url = KeywordElasticsearchType(
        help_text="The URL associated with the web resource.",
    )


class WebRequestMixin(UrlMixin):
    """
    This is a mixin class for Elasticsearch models that are related to an HTTP request.
    """

    request_headers = KeywordKeyValueElasticsearchType(
        index=False,
        help_text="The request headers associated with the web resource.",
    )
    request_method = KeywordElasticsearchType(
        help_text="The HTTP method used to request the referenced web resource.",
    )
    query_arguments = KeywordKeyValueElasticsearchType(
        index=False,
        help_text="The query string arguments found within the request to the referenced web "
                  "resource.",
    )
    body_arguments = KeywordKeyValueElasticsearchType(
        index=False,
        help_text="The body arguments found within the request to the referenced web resource.",
    )
    response_status = IntElasticsearchType(
        help_text="The HTTP status code returned by the request to the referenced web resource.",
    )


class ResourceInfoMixin(object):
    """
    This is a mixin class for Elasticsearch models that contain metadata about a web resource.
    """

    content_type = KeywordElasticsearchType(
        help_text="The MIME content type associated with the resource.",
    )
    content_length = IntElasticsearchType(
        help_text="The length in bytes of the referenced resource.",
    )
    content_hash = KeywordElasticsearchType(
        help_text="A cryptographic hash of the response content returned for the fingerprinting request.",
    )
    content_secondary_hash = KeywordElasticsearchType(
        help_text="A secondary hash representing the content of the referenced resource "
                  "(contents of secondary hash depend on MIME type).",
    )
