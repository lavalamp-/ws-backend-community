# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import DictableMixin
from ..components import TypeFilterComponent


class BaseElasticsearchAggregate(DictableMixin):
    """
    A base class for aggregates placed on Elasticsearch queries.
    """

    # Class Members

    # Instantiation

    def __init__(self, name=None, size=10000, include_size=True):
        self.name = name
        self._filters = []
        self.size = size
        self.include_size = include_size

    # Static Methods

    # Class Methods

    @classmethod
    def unpack_response(cls, response):
        """
        Unpack the contents of the given aggregate response based on the configuration of this aggregate
        and return a list containing the key data points held within.
        :param response: The response to parse as an aggregate.
        :return: A list containing the key data points held within.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    def filter_by_class(self, filter_class):
        """
        Add a filter to this aggregate to restrict aggregate results to the given Elasticsearch model
        class.
        :param filter_class: The Elasticsearch model class to restrict results to.
        :return: None
        """
        self._filters.append(TypeFilterComponent(filter_class))

    # Protected Methods

    def _get_aggregate_dict(self):
        """
        Get the dictionary that should be the value of self.agg_type in the aggregate
        dictionary.
        :return: The dictionary that should be the value of self.agg_type in the aggregate
        dictionary.
        """
        to_return = {}
        if len(self._filters) == 1:
            to_return["filter"] = self._filters[0].to_dict()
        elif len(self._filters) > 1:
            to_return["filters"] = [x.to_dict() for x in self._filters]
        if self.size is not None and self.include_size:
            to_return["size"] = self.size
        return to_return

    # Private Methods

    # Properties

    @property
    def filters(self):
        """
        Get a list of the filters that this aggregate is currently configured to filter upon.
        :return: a list of the filters that this aggregate is currently configured to filter upon.
        """
        return self._filters

    @property
    def key(self):
        return self.name

    @property
    def value(self):
        return self._get_aggregate_dict()

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)


class TermsAggregate(BaseElasticsearchAggregate):
    """
    A class for representing a terms aggregation placed on an Elasticsearch query.
    """

    # Class Members

    # Instantiation

    def __init__(self, field=None, *args, **kwargs):
        super(TermsAggregate, self).__init__(*args, **kwargs)
        self.field = field

    # Static Methods

    # Class Methods

    @classmethod
    def unpack_response(cls, response):
        to_return = []
        for bucket in response["buckets"]:
            to_return.append({
                "label": bucket["key"],
                "count": bucket["doc_count"],
            })
        return to_return

    # Public Methods

    # Protected Methods

    def _get_aggregate_dict(self):
        to_return = super(TermsAggregate, self)._get_aggregate_dict()
        to_return["field"] = self.field
        return {
            "terms": to_return,
        }

    # Private Methods

    # Properties

    # Representation and Comparison
