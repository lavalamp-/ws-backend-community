# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchComponent
from lib import ValidationHelper


class SortComponent(BaseElasticsearchComponent):
    """
    This is a component for handling the sorting of query results.
    """

    # Class Members

    # Instantiation

    def __init__(self):
        self._fields = {}

    # Static Methods

    # Class Methods

    # Public Methods

    def add_field(self, field_name=None, direction="asc"):
        """
        Add the given field as a field to sort by in the given direction.
        :param field_name: The name of the field to sort by.
        :param direction: The direction to sort in.
        :return: None
        """
        ValidationHelper.validate_sort_direction(direction)
        self._fields[field_name] = direction

    # Protected Methods

    # Private Methods

    def __get_sort_body(self):
        """
        Get the body contents for this Elasticsearch sort clause.
        :return: The body contents for this Elasticsearch sort clause.
        """
        to_return = []
        for k, v in self.fields.iteritems():
            to_return.append({k: v})
        return to_return

    # Properties

    @property
    def fields(self):
        """
        Get the fields that this component is currently configured to sort by.
        :return: The fields that this component is currently configured to sort by.
        """
        return self._fields

    @property
    def name(self):
        return "sort"

    @property
    def value(self):
        return self.__get_sort_body()

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)

