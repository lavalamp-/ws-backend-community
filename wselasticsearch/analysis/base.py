# -*- coding: utf-8 -*-
from __future__ import absolute_import


class BaseElasticsearchAnalysis(object):
    """
    This is a base class for all classes meant to perform analytical queries against
    Elasticsearch based on the queries found in wselasticsearch.queries. These classes are intended
    to be used by the rest framework to return analytical data to front-end users.
    """

    # Class Members

    # Instantiation

    def __init__(self):
        self._query = self.analyzed_query_class(size=self.size, suppress_source=True)
        self._aggregate_keys = []
        self._apply_aggregates()

    # Static Methods

    # Class Methods

    @classmethod
    def get_analyzed_query_class(cls):
        """
        Get the query class that this analysis object is meant to run queries upon.
        :return: The query class that this analysis object is meant to run queries upon.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    def aggregate_on_term(self, key=None, name=None):
        """
        Apply the given term aggregate to self.query.
        :param key: The key to aggregate on.
        :param name: The name to give the aggregation.
        :return: None
        """
        self._aggregate_keys.append(name)
        self.query.aggregate_on_term(key=key, name=name)

    def run(self, index=None, unpack=True):
        """
        Run the query and return the resulting response.
        :param index: Index to run the query upon.
        :param unpack: Whether or not to unpack the contents of the Elasticsearch response for use in a
        Django rest framework handler.
        :return: The response returned by Elasticsearch.
        """
        to_return = self.query.search(index=index)
        if unpack:
            return self.unpack_results_from_response(to_return)
        else:
            return to_return

    def unpack_results_from_response(self, response):
        """
        Unpack the contents of the given ElasticsearchQueryResponse for use as data returned by a Django
        rest framework view.
        :param response: The response to unpack.
        :return: A dictionary to return in a Django rest framework view.
        """
        to_return = {}
        for aggregate_key in self.aggregate_keys:
            aggregate_entries = []
            for bucket in response.aggregations[aggregate_key]["buckets"]:
                aggregate_entries.append((bucket["key"], bucket["doc_count"]))
            to_return[aggregate_key] = aggregate_entries
        return to_return

    # Protected Methods

    def _apply_aggregates(self):
        """
        Add all of the necessary aggregates to the queried class.
        :return: None
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    # Properties

    @property
    def aggregate_keys(self):
        """
        Get a list of strings representing the aggregate keys for the aggregates applied to self.query.
        :return: a list of strings representing the aggregate keys for the aggregates applied to self.query.
        """
        return self._aggregate_keys

    @property
    def analyzed_query_class(self):
        """
        Get the query class that this analysis object is meant to run queries upon.
        :return: The query class that this analysis object is meant to run queries upon.
        """
        return self.__class__.get_analyzed_query_class()

    @property
    def query(self):
        """
        Get the Elasticsearch query object that this analysis is built around.
        :return: the Elasticsearch query object that this analysis is built around.
        """
        return self._query

    @property
    def size(self):
        """
        Get the size of the queried results to return.
        :return: the size of the queried results to return.
        """
        return None

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)
