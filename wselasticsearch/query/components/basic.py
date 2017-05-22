# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchComponent


class BasicComponent(BaseElasticsearchComponent):
    """
    A class for representing a basic query component in Elasticsearch.
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


class RangeComponent(BasicComponent):
    """
    A class for representing a range query component in Elasticsearch.
    """

    # Class Members

    # Instantiation

    def __init__(self, key=None, val_from=None, val_to=None):
        self.term_key = key
        self.val_from = val_from
        self.val_to = val_to

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def name(self):
        return "range"

    @property
    def value(self):
        return {
            self.term_key: {
                "from": self.val_from,
                "to": self.val_to,
            }
        }

    # Representation and Comparison


class DateRangeComponent(BasicComponent):
    """
    A class for representing a range query component in Elasticsearch.
    """

    # Class Members

    # Instantiation

    def __init__(self, key=None, datetime_from=None, datetime_to=None):
        self.term_key = key
        self.datetime_from = datetime_from
        self.datetime_to = datetime_to

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def name(self):
        return "range"

    @property
    def value(self):
        return {
            self.term_key: {
                "gte": self.datetime_from.strftime('%Y-%m-%dT%H:%M:%S%z'),
                "lte": self.datetime_to.strftime('%Y-%m-%dT%H:%M:%S%z'),
            }
        }

    # Representation and Comparison


class TermComponent(BasicComponent):
    """
    A class for representing a term query component in Elasticsearch.
    """

    # Class Members

    # Instantiation

    def __init__(self, key=None, value=None):
        self.term_key = key
        self.term_value = value

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def name(self):
        return "term"

    @property
    def value(self):
        return {
            self.term_key: self.term_value,
        }

    # Representation and Comparison


class ExistsComponent(BasicComponent):
    """
    A class for representing an exists query component in Elasticsearch.
    """

    def __init__(self, field=None):
        self.field = field

    @property
    def name(self):
        return "exists"

    @property
    def value(self):
        return {
            "field": self.field,
        }
