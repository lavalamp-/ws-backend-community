# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from lib import DatetimeHelper, ValidationHelper, ConfigManager
from .scripts import BaseSourceElasticsearchScript
from .aggregates import TermsAggregate, HistogramAggregate, CountAggregate, SumAggregate
from .components import TermComponent, RangeComponent, BooleanComponent, DateRangeComponent, SortComponent, \
    WildcardFilterComponent, ExistsComponent
from .mixin import ScanQueryMixin
from .response import ElasticsearchQueryResponse, ElasticsearchUpdateResponse, ElasticsearchDeleteResponse

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


class BaseElasticsearchQuery(object):
    """
    This is a base class for query classes meant to query single Web Sight Elasticsearch models.
    """

    # Class Members

    # Instantiation

    def __init__(
            self,
            size=None,
            offset=None,
            suppress_source=False,
            max_size=False,
    ):
        super(BaseElasticsearchQuery, self).__init__()
        if max_size:
            self.size = config.es_max_query_size
        else:
            self.size = size
        self.offset = offset
        self._component = BooleanComponent()
        self._aggregates = {}
        self._queryable_fields = None
        self.suppress_source = suppress_source
        self._queried_fields = None
        self._script = None
        self._sort = None
        self._search_term = None
        self._search_field = "_all"
        self._search_wild_after = None
        self._search_wild_before = None
        self._es_helper = None

    # Static Methods

    # Class Methods

    @classmethod
    def get_last_diffable_document_by_model(cls, model=None, index=None):
        """
        Get the last-created Elasticsearch document containing data about the data source represented by
        model based on the contents of the diffable keys found in model.
        :param model: The model to base the query from.
        :param index: The index that should be searched in.
        :return: An Elasticsearch model class representing the most recently-gathered data on the referenced
        data source if such a document exists in Elasticsearch, otherwise None.
        """
        query = cls(size=1, offset=0)
        for k, v in model.get_diff_key_kwargs().iteritems():
            query.must_by_term(key=k, value=v)
        if model.id:
            query.must_by_term(key="_id", value=model.id, include=False)
        result = query.search(index)
        if result.results_count == 0:
            return None
        else:
            queried_class = cls.get_queried_class()
            return queried_class.from_response_result(result.results[0])

    @classmethod
    def get_queried_class(cls):
        """
        Get the model class that this query is configured to run against.
        :return: The model class that this query is configured to run against.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @classmethod
    def get_queryable_fields(cls):
        """
        Get a list containing all of the fields that can be queried by this query class.
        :return: A list containing all of the fields that can be queried by this query class.
        """
        return cls.get_queried_class().get_all_mapping_fields()

    # Public Methods

    def add_aggregate(self, aggregate):
        """
        Add the given aggregate to the current query DSL.
        :param aggregate: The aggregate to add.
        :return: None
        """
        ValidationHelper.validate_not_in(
            to_check=aggregate.name,
            contained_by=self._aggregates.keys(),
        )
        self._aggregates[aggregate.name] = aggregate

    def add_queried_field(self, field_name):
        """
        Add the given field as a field to be queried.
        :param field_name: The field to be queried.
        :return: None
        """
        self._validate_queryable_field(field_name)
        if self._queried_fields is None:
            self._queried_fields = [field_name]
        else:
            self._queried_fields.append(field_name)
            self._queried_fields = list(set(self._queried_fields))

    def add_sort_field(self, field_name=None, direction="asc"):
        """
        Add a clause to this Elasticsearch query to sort results by the given field and
        direction.
        :param field_name: The name of the field to sort on.
        :param direction: The direction to sort in.
        :return: None
        """
        self._validate_queryable_field(field_name)
        if self._sort is None:
            self._sort = SortComponent()
        self._sort.add_field(field_name=field_name, direction=direction)

    def aggregate_with_histogram(self, key=None, name=None, interval=None):
        """
        Add an aggregation to the query that will create a histogram for the given key
        along the given intervals.
        :param key: The key to aggregate on.
        :param name: The name fo give the aggregation.
        :param interval: The interval to create histogram buckets with.
        :return: None
        """
        self._validate_queryable_field(key)
        histogram_aggregate = HistogramAggregate(field=key, name=name, interval=interval)
        self.add_aggregate(histogram_aggregate)

    def aggregate_with_sum(self, key=None, name=None):
        """
        Add an aggregation to the query that will sum up all of the values in the given
        field.
        :param key: The key to aggregate on.
        :param name: The name to give the aggregate.
        :return: None
        """
        self._validate_queryable_field(key)
        sum_aggregate = SumAggregate(field=key, name=name)
        self.add_aggregate(sum_aggregate)

    def aggregate_on_term(self, key=None, name=None):
        """
        Add an aggregation to the query that will aggregate on the given key.
        :param key: The key to aggregate on.
        :param name: The name to give the aggregation.
        :return: None
        """
        name = key if name is None else name
        self._validate_queryable_field(key)
        terms_aggregate = TermsAggregate(field=key, name=name)
        self.add_aggregate(terms_aggregate)

    def count_term(self, key=None, name=None, value=None):
        """
        Add an aggregation to the query that will count the instances of term_field found on the queried
        documents with the value value.
        :param key: The key to count instances of.
        :param name: The name to give the aggregation.
        :param value: The value to count.
        :return: None
        """
        self._validate_queryable_field(key)
        count_aggregate = CountAggregate(field=key, term_value=value, name=name)
        self.add_aggregate(count_aggregate)

    def delete_by_query(self, index):
        """
        Delete all of the documents matching the current query in the given index.
        :param index: The index to delete from.
        :return: An ElasticsearchDeleteResponse wrapping the response received from the Elasticsearch
        endpoint.
        """
        to_return = self.es_helper.delete_model_by_query(query=self, index=index)
        return ElasticsearchDeleteResponse(to_return)

    def field_exists(self, field=None, include=True):
        """
        Add a component to this query that restricts results to those that have a non-null value in
        the given field.
        :param field: The field to query against.
        :param include: Whether to include all results that contain a non-null value in the given field,
        or whether to exclude them.
        :return: None
        """
        self._validate_queryable_field(field)
        component_as = "must" if include else "must_not"
        self.__add_component(ExistsComponent(field), component_as=component_as)

    def must_by_datetime_range(self, key=None, r_from_datetime=None, r_to_datetime=None, include=True):
        """
        Add a query filter that requires the given key to have a value in the specified range.
        :param key: The object key to check.
        :param r_from_datetime: The beginning of the range to search in.
        :param r_to_datetime: The end of the range to search in.
        :param include: Whether the query should search FOR or NOT FOR the given term.
        :return: None
        """
        self._validate_queryable_field(key)
        component_as = "must" if include else "must_not"
        self.__add_component(DateRangeComponent(key=key, datetime_from=r_from_datetime, datetime_to=r_to_datetime), component_as=component_as)

    def must_by_range(self, key=None, r_from=None, r_to=None, include=True):
        """
        Add a query filter that requires the given key to have a value in the specified range.
        :param key: The object key to check.
        :param r_from: The beginning of the range to search in.
        :param r_to: The end of the range to search in.
        :param include: Whether the query should search FOR or NOT FOR the given term.
        :return: None
        """
        self._validate_queryable_field(key)
        component_as = "must" if include else "must_not"
        self.__add_component(RangeComponent(key=key, val_from=r_from, val_to=r_to), component_as=component_as)

    def must_by_term(self, key=None, value=None, include=True, verify_key=True):
        """
        Add a query filter that requires the given key to match the given value.
        :param key: The object key to check.
        :param value: The value that it must be.
        :param include: Whether the query should search FOR or NOT FOR the given term.
        :param verify_key: Whether or not to validate that key is a field explicitly declared on the
        queried model.
        :return: None
        """
        if verify_key:
            self._validate_queryable_field(key)
        component_as = "must" if include else "must_not"
        self.__add_component(TermComponent(key=key, value=value), component_as=component_as)

    def must_by_wildcard(self, key=None, value=None, include=True, wild_before=True, wild_after=True):
        """
        Add a query filter that requires the given key to contain the given value.
        :param key: The key to check.
        :param value: The contents to search for.
        :param include: Whether the query should search FOR or NOT FOR the given wildcard value.
        :param wild_before: Whether or not to have a wildcard at the beginning of value.
        :param wild_after: Whether or not to have a wildcard at the end of value.
        :return: None
        """
        self._validate_queryable_field(key)
        component_as = "must" if include else "must_not"
        self.__add_component(WildcardFilterComponent(
            field=key,
            term=value,
            wild_before=wild_before,
            wild_after=wild_after
        ), component_as=component_as)

    def or_by_term(self, key=None, value=None, verify_key=True):
        """
        Add a query filter that adds the given key-value match to the list of conditional OR operations
        associated with the query.
        :param key: The key to match on.
        :param value: The value to match on.
        :param verify_key: Whether or not to validate that key is a field explicitly declared on the queried
        model.
        :return: None
        """
        if verify_key:
            self._validate_queryable_field(key)
        self.__add_component(TermComponent(key=key, value=value), component_as="or")

    def or_by_wildcard(self, key=None, value=None, wild_before=True, wild_after=True):
        """
        Add a query filter that includes the given wildcard value in the boolean "should" component
        (logical OR).
        :param key: The key to check.
        :param value: The contents to search for.
        :param wild_before: Whether or not to have a wildcard at the beginning of value.
        :param wild_after: Whether or not to have a wildcard at the end of value.
        :return: None
        """
        self._validate_queryable_field(key)
        self.__add_component(WildcardFilterComponent(
            field=key,
            term=value,
            wild_before=wild_before,
            wild_after=wild_after,
        ), component_as="or")

    def search(self, index=None):
        """
        Perform the query as configured by this object's internal state and return the results.
        :param index: The index to search in.
        :return: The results of the query.
        """
        to_return = self.es_helper.search_index(
            index=index,
            doc_type=self.doc_type,
            body=self.to_query_dict(),
        )
        return ElasticsearchQueryResponse(to_return)

    def set_search_term(self, term=None, field="_all", wild_before=True, wild_after=True):
        """
        Set the field that should be searched for and the term that should be searched for in the
        query.
        :param term: A string representing the term that the search contain.
        :param field: A string containing the field that the search should be done in.
        :param wild_before: Whether or not to provide wildcard search before the term.
        :param wild_after: Whether or not to provide wildcard search after the term.
        :return: None
        """
        self._search_term = term
        self._search_field = field
        self._search_wild_before = wild_before
        self._search_wild_after = wild_after

    def to_body(self):
        """
        Get a Python dictionary that represents this entire query for use as a body argument
        in an Elasticsearch query.
        :return: A Python dictionary that represents this entire query for use as a body argument
        in an Elasticsearch query.
        """
        to_return = {
            "query": self.component.to_dict(),
        }
        if self.size is not None:
            to_return["size"] = self.size
        if self.offset is not None:
            to_return["offset"] = self.offset
        return to_return

    def to_query_dict(self):
        """
        Get a Python dictionary that represents the query specified by self.component.
        :return: A Python dictionary that represents the query specified by self.component.
        """
        if self.search_term is not None:
            self.__add_component(WildcardFilterComponent(
                field=self.search_field,
                term=self.search_term,
                wild_before=self.search_wild_before,
                wild_after=self.search_wild_after,
            ), component_as="must")
        to_return = {"query": self.component.to_dict()}
        if len(self.aggregates) > 0:
            to_return["aggs"] = {}
            for aggregate in self.aggregates.values():
                to_return["aggs"].update(aggregate.to_dict())
        if self.suppress_source:
            to_return["_source"] = False
        elif self.queried_fields is not None:
            to_return["_source"] = self.queried_fields
        if self.script is not None:
            to_return.update(self.script.to_dict())
        if self.size is not None:
            to_return["size"] = self.size
        if self.offset is not None:
            to_return["from"] = self.offset
        if self.sort is not None:
            to_return.update(self.sort.to_dict())
        return to_return

    def update_by_query(self, index):
        """
        Perform an update_by_query operation based on the contents of this query for the given
        index.
        :param index: The index to update by query.
        :return: The results of the Elasticsearch call.
        """
        to_return = self.es_helper.update_model_by_query(query=self, index=index)
        return ElasticsearchUpdateResponse(to_return)

    def update_field(self, key=None, value=None):
        """
        Add a script line to this query that updates the given field on this model to the given value.
        :param key: The key to update.
        :param value: The value to update it to.
        :return: None
        """
        self._validate_queryable_field(key)
        if self._script is None:
            self._script = BaseSourceElasticsearchScript()
        self._script.add_equals(key=key, value=value)

    def update_field_to_now(self, key):
        """
        Add a script line to this query that updates the given field on this model to the current datetime.
        :param key: The key to update.
        :return: None
        """
        self.update_field(key=key, value=DatetimeHelper.now())

    # Protected Methods

    def _validate_queryable_field(self, field):
        """
        Validate that the given field is a field that can be queried upon in self.queried_class.
        :param field: The field to check.
        :return: None
        """
        if "." in field:
            field = field[:field.find(".")]
        ValidationHelper.validate_in(to_check=field, contained_by=self.queryable_fields)

    # Private Methods

    def __add_component(self, component, component_as="filter"):
        """
        Add the given component to the current query DSL.
        :param component: The component to add.
        :return: None
        """
        ValidationHelper.validate_es_component_as(component_as)
        if component_as == "filter":
            self._component.add_filter(component)
        elif component_as == "must":
            self._component.add_must(component)
        elif component_as == "must_not":
            self._component.add_must_not(component)
        elif component_as == "should":
            self._component.add_should(component)
        elif component_as == "or":
            self._component.add_or(component)
        else:
            raise TypeError(
                "Unsure how to handle component_as value of %s."
                % (component_as,)
            )

    # Properties

    @property
    def aggregates(self):
        """
        Get a list of aggregates to apply to the query.
        :return: a list of aggregates to apply to the query.
        """
        return self._aggregates

    @property
    def component(self):
        """
        Get the query component currently prepared for this query.
        :return: a the query component currently prepared for this query.
        """
        return self._component

    @property
    def es_helper(self):
        """
        Get the ElasticsearchHelper to use to query Elasticsearch.
        :return: the ElasticsearchHelper to use to query Elasticsearch.
        """
        if self._es_helper is None:
            from ..helper import ElasticsearchHelper
            self._es_helper = ElasticsearchHelper.instance()
        return self._es_helper

    @property
    def doc_type(self):
        """
        Get the document type that this query class is configured to search against.
        :return: The document type that this query class is configured to search against.
        """
        return self.queried_class.get_doc_type()

    @property
    def queried_class(self):
        """
        Get the model class that this query is configured to run against.
        :return: The model class that this query is configured to run against.
        """
        return self.__class__.get_queried_class()

    @property
    def queried_fields(self):
        """
        Get a list of the fields that the query is configured to return, or None if all
        fields will be returned.
        :return: a list of the fields that the query is configured to return, or None
        if all fields will be returned.
        """
        return self._queried_fields

    @queried_fields.setter
    def queried_fields(self, new_value):
        """
        Set the fields that should be queried.
        :param new_value: A list of fields to query, or a string representing a single field.
        :return: None
        """
        if isinstance(new_value, list):
            for field_name in new_value:
                self.add_queried_field(field_name)
        else:
            self.add_queried_field(new_value)

    @property
    def queryable_fields(self):
        """
        Get a list of strings representing the fields that can be queried in self.queried_class.
        :return: A list of strings representing the fields that can be queried in self.queried_class.
        """
        return self.__class__.get_queryable_fields()

    @property
    def script(self):
        """
        Get the script object that this query is currently configured to run.
        :return: the script object that this query is currently configured to run.
        """
        return self._script

    @property
    def search_term(self):
        """
        Get the search term that should be included in the query.
        :return: the search term that should be included in the query.
        """
        return self._search_term

    @property
    def search_field(self):
        """
        Get the field that the search term should be searched in.
        :return: The field that the search term should be searched in. 
        """
        return self._search_field

    @property
    def search_wild_after(self):
        """
        Get whether or not the wildcard search term should provide wildcard matching after the 
        search term.
        :return: whether or not the wildcard search term should provide wildcard matching after 
        the search term.
        """
        return self._search_wild_after

    @property
    def search_wild_before(self):
        """
        Get whether or not the wildcard search term should provide wildcard matching before the 
        search term.
        :return: whether or not the wildcard search term should provide wildcard matching before 
        the search term.
        """
        return self._search_wild_before

    @property
    def sort(self):
        """
        Get the sort component that this query is currently configured to use.
        :return: the sort component that this query is currently configured to use.
        """
        return self._sort

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.queried_class.__name__)


class BaseElasticsearchModelQuery(BaseElasticsearchQuery):
    """
    This is a base query class that queries results based on a single model class.
    """

    def get(self, index=None, doc_id=None, *args, **kwargs):
        """
        Get the instance of the queried model that matches the given document ID.
        :param index: The index to search in.
        :param doc_id: The ID of the document to retrieve.
        :param args: Positional arguments for the get query.
        :param kwargs: Keyword arguments for the get query.
        :return: An Elasticsearch model class matching the given ID if such a document exists.
        """
        if self.queried_fields is not None:
            kwargs["_source_include"] = self.queried_fields
        response = self.es_helper.get_document(
            index=index,
            doc_type=self.doc_type,
            doc_id=doc_id,
            *args,
            **kwargs
        )
        return self.queried_class.from_response_result(response)


class BaseMappedElasticsearchQuery(BaseElasticsearchModelQuery):
    """
    This is a base query class for Elasticsearch models that are mapped to database models.
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

