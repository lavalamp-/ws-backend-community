# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchAggregate


class NestedElasticsearchAggregate(BaseElasticsearchAggregate):
    """
    This is an aggregate class that handles Elasticsearch aggregations that are nested.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        kwargs["include_size"] = False
        super(NestedElasticsearchAggregate, self).__init__(*args, **kwargs)
        self._child_aggregates = []

    # Static Methods

    # Class Methods

    # Public Methods

    def add_child_terms_aggregate(self, name=None, field=None, size=10000):
        """
        Add a terms aggregate to this aggregate as a child.
        :param name: The name to assign to the aggregate.
        :param field: The field to aggregate terms of.
        :param size: The size for the aggregate.
        :return: None
        """
        from .base import TermsAggregate
        new_aggregate = TermsAggregate(field=field, size=size, name=name)
        self.add_child_aggregate(new_aggregate)

    def add_child_aggregate(self, child_aggregate):
        """
        Add the given aggregate as a child aggregate to for this aggregate.
        :param child_aggregate: The child aggregate to add to self.
        :return: None
        """
        self._child_aggregates.append(child_aggregate)

    # Protected Methods

    def _get_aggregate_dict(self):
        to_return = super(NestedElasticsearchAggregate, self)._get_aggregate_dict()
        if len(self._child_aggregates) > 0:
            agg_dict = {}
            for child_aggregate in self._child_aggregates:
                agg_dict.update(child_aggregate.to_dict())
            to_return["aggs"] = agg_dict
        return to_return

    # Private Methods

    # Properties

    @property
    def child_aggregates(self):
        """
        Get a list of nested child aggregates for this aggregate.
        :return: a list of nested child aggregates for this aggregate.
        """
        return self._child_aggregates

    # Representation and Comparison
