# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..types import *


class UrlMixin(object):
    """
    This is a mixin class for Elasticsearch models that are related to a single URL.
    """

    url = KeywordElasticsearchType()


class WebRequestMixin(UrlMixin):
    """
    This is a mixin class for Elasticsearch models that are related to an HTTP request.
    """

    request_headers = KeywordKeyValueElasticsearchType(index=False)
    request_method = KeywordElasticsearchType()
    query_arguments = KeywordKeyValueElasticsearchType(index=False)
    body_arguments = KeywordKeyValueElasticsearchType(index=False)
    response_status = IntElasticsearchType()


class ResourceInfoMixin(object):
    """
    This is a mixin class for Elasticsearch models that contain metadata about a web resource.
    """

    content_type = KeywordElasticsearchType()
    content_length = IntElasticsearchType()
    content_hash = KeywordElasticsearchType()
    content_secondary_hash = KeywordElasticsearchType()
