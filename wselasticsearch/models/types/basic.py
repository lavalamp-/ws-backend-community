# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchType


class BooleanElasticsearchType(BaseElasticsearchType):
    """
    A class for representing a boolean Elasticsearch type.
    """

    @property
    def type(self):
        return "boolean"


class IntElasticsearchType(BaseElasticsearchType):
    """
    A class for representing an integer Elasticsearch type.
    """

    @property
    def type(self):
        return "integer"


class LongElasticsearchType(BaseElasticsearchType):
    """
    A class for representing a long Elasticsearch type.
    """

    @property
    def type(self):
        return "long"


class DoubleElasticsearchType(BaseElasticsearchType):
    """
    A class for representing a double Elasticsearch type.
    """

    @property
    def type(self):
        return "double"


class DateElasticsearchType(BaseElasticsearchType):
    """
    A class for representing a date Elasticsearch type.
    """
    @property
    def type(self):
        return "date"


class KeywordElasticsearchType(BaseElasticsearchType):
    """
    A class for representing a keyword Elasticsearch type.
    """

    @property
    def type(self):
        return "keyword"


class IpElasticsearchType(BaseElasticsearchType):
    """
    A class for representing an IP Elasticsearch type.
    """

    @property
    def type(self):
        return "ip"


class ObjectElasticsearchType(BaseElasticsearchType):
    """
    A class for representing an object Elasticsearch type.
    """

    @property
    def type(self):
        return "object"


class TextElasticsearchType(BaseElasticsearchType):
    """
    A class for representing a text Elasticsearch type.
    """

    @property
    def type(self):
        return "text"


class GeopointElasticsearchType(BaseElasticsearchType):
    """
    A class for representing a geopoint Elasticsearch type.
    """

    @property
    def type(self):
        return "geo_point"
