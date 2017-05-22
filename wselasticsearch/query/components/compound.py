# -*- coding: utf-8 -*-
from __future__ import absolute_import

from collections import defaultdict

from lib import ValidationHelper
from .base import BaseElasticsearchComponent


class CompoundComponent(BaseElasticsearchComponent):
    """
    A class for representing a compound query component in Elasticsearch.
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


class BooleanComponent(CompoundComponent):
    """
    A class for representing a boolean query component in Elasticsearch.
    """

    # Class Members

    # Instantiation

    def __init__(self):
        self._must = []
        self._must_not = []
        self._should = []
        self._filter = []
        self._or_components = []

    # Static Methods

    # Class Methods

    # Public Methods

    def add_filter(self, component):
        """
        Add the specified component as a "filter" component.
        :param component: The component to add.
        :return: None
        """
        ValidationHelper.validate_es_component_type(component)
        self._filter.append(component)

    def add_must(self, component):
        """
        Add the specified component as a "must" component.
        :param component: The component to add.
        :return: None
        """
        ValidationHelper.validate_es_component_type(component)
        self._must.append(component)

    def add_must_not(self, component):
        """
        Add the specified component as a "must" component.
        :param component: The component to add.
        :return: None
        """
        ValidationHelper.validate_es_component_type(component)
        self._must_not.append(component)

    def add_should(self, component):
        """
        Add the specified component as a "should" component.
        :param component: The component to add.
        :return: None
        """
        ValidationHelper.validate_es_component_type(component)
        self._should.append(component)

    def add_or(self, component):
        """
        Add the specified component as part of the list of "OR" components contained
        by this BooleanComponent.
        :param component: The component to add.
        :return: None
        """
        ValidationHelper.validate_es_component_type(component)
        self._or_components.append(component)

    # Protected Methods

    # Private Methods

    def __consolidate_components(self, components):
        """
        Consolidate the list of components into a single dictionary.
        :param components: A list of components to process.
        :return: A single dictionary representing the list of components.
        """
        to_return = {}
        for component in components:
            if component.name not in to_return:
                to_return[component.name] = component.value
            elif isinstance(to_return[component.name], dict):
                to_return[component.name] = [to_return[component.name], component.value]
            else:
                to_return[component.name].append(component.value)
            print(to_return)
        return to_return

    def __get_value(self):
        """
        Calculate and return the query dictionary value for the current state of this
        component.
        :return: The query dictionary value for the current state of this component.
        """
        to_return = {}
        if len(self.must) > 0:
            to_return["must"] = [x.to_dict() for x in self.must]
        if len(self.must_not) > 0:
            to_return["must_not"] = [x.to_dict() for x in self.must_not]
        if len(self.filter) > 0:
            to_return["filter"] = [x.to_dict() for x in self.filter]
        if len(self.should) > 0:
            to_return["should"] = [x.to_dict() for x in self.should]
        if len(self.or_components) > 0:
            if "filter" not in to_return:
                to_return["filter"] = []
            or_filter = BooleanComponent()
            for or_component in self.or_components:
                or_filter.add_should(or_component)
            to_return["filter"].append(or_filter.to_dict())
        return to_return

    # Properties

    @property
    def filter(self):
        """
        Get the list of Elasticsearch components for the filter section of the query.
        :return: the list of Elasticsearch components for the filter section of the query.
        """
        return self._filter

    @property
    def must(self):
        """
        Get the list of Elasticsearch components for the must section of the query.
        :return: the list of Elasticsearch components for the must section of the query.
        """
        return self._must

    @property
    def must_not(self):
        """
        Get the list of Elasticsearch components for the must_not section of the query.
        :return: the list of Elasticsearch components for the must_not section of the query.
        """
        return self._must_not

    @property
    def name(self):
        return "bool"

    @property
    def or_components(self):
        """
        Get the list of components that are being used as the logical OR in this query.
        :return: the list of components that are being used as the logical OR in this query.
        """
        return self._or_components

    @property
    def should(self):
        """
        Get the list of Elasticsearch components for the should section of the query.
        :return: the list of Elasticsearch components for the should section of the query.
        """
        return self._should

    @property
    def value(self):
        return self.__get_value()

    # Representation and Comparison
