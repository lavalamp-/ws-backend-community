# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchComponent
from lib import ValidationHelper


class BaseElasticsearchFilterComponent(BaseElasticsearchComponent):
    """
    This is a base component for all components that represent Elasticsearch filters.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def type(self):
        """
        Get the type of filter that this component represents.
        :return: the type of filter that this component represents.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Representation and Comparison


class TypeFilterComponent(BaseElasticsearchFilterComponent):
    """
    This is a filter component that enables Elasticsearch queries to filter based on
    document type.
    """

    # Class Members

    # Instantiation

    def __init__(self, filter_class):
        """
        Initialize this filter component to have a reference to the class that it should filter
        upon.
        :param filter_class: The Elasticsearch model class to filter on.
        """
        ValidationHelper.validate_es_model_class(filter_class)
        self._filter_class = filter_class

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def filter_class(self):
        """
        Get the Elasticsearch model class to filter on.
        :return: The Elasticsearch model class to filter on.
        """
        return self._filter_class

    @property
    def name(self):
        return "type"

    @property
    def value(self):
        return {
            "value": self.filter_class.get_doc_type(),
        }

    # Representation and Comparison


class WildcardFilterComponent(BaseElasticsearchFilterComponent):
    """
    This is a component for representing a wildcard filter clause.
    """

    # Class Members

    # Instantiation

    def __init__(self, field=None, term=None, wild_before=True, wild_after=True):
        self._field = field
        self._term = term
        self.wild_before = wild_before
        self.wild_after = wild_after

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def field(self):
        """
        Get the field that this wildcard filter is filtering upon.
        :return: the field that this wildcard filter is filtering upon.
        """
        return self._field

    @property
    def filter_string(self):
        """
        Get the string that should be used for the wildcard filter value.
        :return: the string that should be used for the wildcard filter value.
        """
        return "%s%s%s" % (
            "*" if self.wild_before else "",
            self.term,
            "*" if self.wild_after else "",
        )

    @property
    def name(self):
        return "wildcard"

    @property
    def term(self):
        """
        Get the term that this wildcard filter is meant to filter upon.
        :return: The term that this wildcard filter is meant to filter upon.
        """
        return self._term

    @property
    def value(self):
        return {self.field: self.filter_string}

    # Representation and Comparison
