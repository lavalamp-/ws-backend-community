# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseElasticsearchQuery
from ..mixin import OrganizationQueryMixin
from lib import ValidationHelper
from ..aggregates import NestedElasticsearchAggregate


class BaseMultidocQuery(BaseElasticsearchQuery):
    """
    This is a base class for query classes that query multiple document types.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        return cls.get_queried_classes()

    @classmethod
    def get_queried_classes(cls):
        """
        Get a list of the classes that this query is configured to query against.
        :return: A list of the classes that this query is configured to query against.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @classmethod
    def get_queryable_fields(cls):
        query_fields = []
        for queried_class in cls.get_queried_classes():
            query_fields.extend(queried_class.get_all_mapping_fields())
        return list(set(query_fields))

    # Public Methods

    def add_aggregate_for_class(self, model_class=None, aggregate=None):
        """
        Add the given aggregate to the nested aggregates currently held by this object for the given
        class.
        :param model_class: The model class to add the aggregate for.
        :param aggregate: The aggregate to add.
        :return: None
        """
        ValidationHelper.validate_in(to_check=model_class, contained_by=self.queried_classes)
        doc_type = model_class.get_doc_type()
        if doc_type not in self._aggregates:
            nested_aggregate = NestedElasticsearchAggregate(name=doc_type)
            nested_aggregate.filter_by_class(model_class)
            self.add_aggregate(nested_aggregate)
        self._aggregates[doc_type].add_child_aggregate(aggregate)

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def doc_type(self):
        return ",".join([x.get_doc_type() for x in self.queried_classes])

    @property
    def queried_classes(self):
        """
        Get a list of the classes that this query queries against.
        :return: a list of the classes that this query queries against.
        """
        return self.__class__.get_queried_classes()

    # Representation and Comparison


class BaseOrganizationMultidocQuery(BaseMultidocQuery, OrganizationQueryMixin):
    """
    This is a base class for multidoc queries that want to filter on organizations.
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
