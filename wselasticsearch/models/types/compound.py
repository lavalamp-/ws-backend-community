# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseComplexElasticsearchType
from .basic import *


class KeyValueElasticsearchType(BaseComplexElasticsearchType):
    """
    A class for representing a key-value mapping.
    """

    # Class Members

    # Instantiation

    def __init__(self, key_type=None, value_type=None, key_name="key", value_name="value", **kwargs):
        super(KeyValueElasticsearchType, self).__init__(**kwargs)
        self.key_type = key_type
        self.value_type = value_type
        self.key_name = key_name
        self.value_name = value_name

    # Static Methods

    # Class Methods

    # Public Methods

    def to_dict(self):
        if self.index:
            key_type = self.key_type(index=self.index).to_dict()
            value_type = self.value_type(index=self.index).to_dict()
        else:
            key_type = self.key_type().to_dict()
            value_type = self.value_type().to_dict()
        return {
            "type": self.type,
            "properties": {
                self.key_name: key_type,
                self.value_name: value_type,
            }
        }

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class KeywordKeyValueElasticsearchType(KeyValueElasticsearchType):
    """
    A class for representing a key-value mapping where both the key and value are strings.
    """

    def __init__(self, **kwargs):
        kwargs["key_type"] = KeywordElasticsearchType
        kwargs["value_type"] = KeywordElasticsearchType
        super(KeywordKeyValueElasticsearchType, self).__init__(**kwargs)


class KeywordIntKeyValueElasticsearchType(KeyValueElasticsearchType):
    """
    A class for representing a key-value mapping where the key is a keyword and the value is an
    integer.
    """

    def __init__(self, **kwargs):
        kwargs["key_type"] = KeywordElasticsearchType
        kwargs["value_type"] = IntElasticsearchType
        super(KeywordIntKeyValueElasticsearchType, self).__init__(**kwargs)


class KeywordTextKeyValueElasticsearchType(KeyValueElasticsearchType):
    """
    A class for representing a key-value mapping where the key is a keyword and the value
    is text.
    """

    def __init__(self, **kwargs):
        kwargs["key_type"] = KeywordElasticsearchType
        kwargs["value_type"] = TextElasticsearchType
        super(KeywordTextKeyValueElasticsearchType, self).__init__(**kwargs)


class KeywordBooleanKeyValueElasticsearchType(KeyValueElasticsearchType):
    """
    A class for representing a key-value apping where the key is a keyword and the value is
    a boolean.
    """

    def __init__(self, **kwargs):
        kwargs["key_type"] = KeywordElasticsearchType
        kwargs["value_type"] = BooleanElasticsearchType
        super(KeywordBooleanKeyValueElasticsearchType, self).__init__(**kwargs)


class CountDataPointElasticsearchType(KeywordIntKeyValueElasticsearchType):
    """
    A class for representing a data point that is a dictionary containing a label (keyword) and a
    count value (int).
    """

    def __init__(self, **kwargs):
        kwargs["key_name"] = "label"
        kwargs["value_name"] = "count"
        super(CountDataPointElasticsearchType, self).__init__(**kwargs)

