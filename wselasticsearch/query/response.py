# -*- coding: utf-8 -*-
from __future__ import absolute_import


class BaseElasticsearchResponse(object):
    """
    This is a base class for wrapping responses received by Elasticsearch.
    """

    # Class Members

    # Instantiation

    def __init__(self, response):
        self.response = response

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)


class ElasticsearchQueryResponse(BaseElasticsearchResponse):
    """
    This is a base class for wrapping responses received by Elasticsearch.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def get_field_from_results(self, field_name):
        """
        Get the values of every instance of the given field name found in self.results.
        :param field_name: The field name to retrieve.
        :return: A list containing the values of every instance of the given field name
        found in self.results.
        """
        return [x["_source"][field_name] for x in self.results]

    def get_fields_from_results(self, field_names):
        """
        Get a list of tuples containing the contents of the given fields in the results of
        this response, in the specified order.
        :param field_names: A list of the field names to retrieve data for.
        :return: A list of tuples containing the contents of the given fields in the results
        of this response.
        """
        to_return = []
        for result in self.results:
            result_list = []
            for field_name in field_names:
                result_list.append(result["_source"][field_name])
            to_return.append(tuple(result_list))
        return to_return

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def aggregations(self):
        """
        Get the aggregations dictionary from this Elasticsearch response.
        :return: The aggregations dictionary from this Elasticsearch response.
        """
        return self.response["aggregations"]

    @property
    def has_results(self):
        """
        Get whether or not results were returned in the response.
        :return: whether or not results were returned in the response.
        """
        return self.results_count > 0

    @property
    def results(self):
        """
        Get a list of the hits returned in the response.
        :return: a list of the hits returned in the response.
        """
        return self.response["hits"]["hits"] if self.has_results else []

    @property
    def results_count(self):
        """
        Get the number of results returned by Elasticsearch.
        :return: the number of results returned by Elasticsearch.
        """
        return self.response["hits"]["total"]

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)


class ElasticsearchUpdateResponse(BaseElasticsearchResponse):
    """
    Documentation for ElasticsearchUpdateResponse.
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
    def updated_count(self):
        """
        Get the number of documents that were updated.
        :return: the number of documents that were updated.
        """
        return self.response["updated"]

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)


class ElasticsearchDeleteResponse(BaseElasticsearchResponse):
    """
    This is an Elasticsearch response class for wrapping responses for deletion queries.
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
    def deleted_count(self):
        """
        Get the number of objects that were deleted as a result of the related request.
        :return: the number of objects that were deleted as a result of the related request.
        """
        return self.response["deleted"]

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)
