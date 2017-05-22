# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist
from django.http import Http404
from django.shortcuts import get_object_or_404
from rest_framework.settings import api_settings

from ..mixin import BaseElasticsearchAPIViewMixin
from lib import ValidationHelper, ConfigManager, get_export_type_wrapper_map
from rest.lib import PaginationSerializer
from .exception import TooManyEsResultsError

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


class BaseElasticsearchMappedAPIViewMixin(BaseElasticsearchAPIViewMixin):
    """
    This is a base mixin for all Elasticsearch APIView classes that query Elasticsearch models which are
    mapped to database model instances.
    """

    # Class Members

    _db_object = None
    _filter_by_parent_db_object = True

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_db_model_class(cls):
        """
        Get the database model class that this APIView is meant to query against.
        :return: The database model class that this APIView is meant to query against.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    # Protected Methods

    def _check_permissions(self):
        return self._check_db_object_permissions()

    def _check_db_object_permissions(self):
        """
        Check to see if the requesting user has sufficient permissions to be querying self.db_object.
        :return: True if the requesting user has sufficient permissions to be querying self.db_object, False
        otherwise.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    def __get_db_object(self):
        """
        Get the database object that the queried Elasticsearch data should be tied to.
        :return: The database object that the queried Elasticsearch data should be tied to.
        """
        to_return = get_object_or_404(self.db_model_class, pk=self.kwargs["pk"])
        return to_return

    # Properties

    @property
    def db_object(self):
        """
        Get the database object that the queried Elasticsearch data should be tied to.
        :return: the database object that the queried Elasticsearch data should be tied to.
        """
        if self._db_object is None:
            self._db_object = self.__get_db_object()
        return self._db_object

    @property
    def db_model_class(self):
        """
        Get the database model class that this APIView is meant to query against.
        :return: The database model class that this APIView is meant to query against.
        """
        return self.__class__.get_db_model_class()

    @property
    def filter_by_parent_db_object(self):
        """
        Get whether or not Elasticsearch results should be filtered upon based on the mapped database object.
        :return: whether or not Elasticsearch results should be filtered upon based on the mapped database object.
        """
        return self._filter_by_parent_db_object

    # Representation and Comparison


class BaseElasticsearchSingleMappedAPIViewMixin(BaseElasticsearchMappedAPIViewMixin):
    """
    This is a base mixin class for all Web Sight APIView classes that query single instances of
    Elasticsearch models that are in turn paired with database models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def _extract_contents_from_response(self, response):
        if response.results_count > 1:
            raise TooManyEsResultsError(
                "Total of %s results retrieved in call to %s."
                % (response.results_count, self.__class__.__name__)
            )
        elif response.results_count == 0:
            raise Http404
        else:
            return self._get_object_from_result(response.results[0])

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseElasticsearchFilterableMappedAPIViewMixin(BaseElasticsearchMappedAPIViewMixin):
    """
    This is a base mixin class for Elasticsearch query classes that enable clients to filter results of
    the Elasticsearch query.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def get(self, *args, **kwargs):
        to_return = super(BaseElasticsearchFilterableMappedAPIViewMixin, self).get(*args, **kwargs)
        to_return.data["filterable_fields"] = self.filterable_fields
        return to_return

    # Protected Methods

    def _apply_filters_to_query(self, query):
        query = super(BaseElasticsearchFilterableMappedAPIViewMixin, self)._apply_filters_to_query(query)
        query = self.__apply_query_string_filters(query)
        return query

    # Private Methods

    def __apply_query_string_filters(self, query):
        """
        Apply filters to the given query based on the contents of the query string in self.request.
        :param query: The query to add filters to.
        :return: The query with filters added.
        """
        for filter_key in self.hard_filterable_fields:
            if filter_key in self.request.query_params:
                filter_value = self.request.query_params.get(filter_key)
                query.must_by_term(key=filter_key, value=filter_value, verify_key=True, include=True)
            elif "-%s" % (filter_key,) in self.request.query_params:
                filter_value = self.request.query_params.get("-%s" % (filter_key,))
                query.must_by_term(key=filter_key, value=filter_value, verify_key=True, include=False)
        for filter_key in self.soft_filterable_fields:
            if filter_key in self.request.query_params:
                filter_value = self.request.query_params.get(filter_key)
                query.must_by_term(key=filter_key, value=filter_value, verify_key=False, include=True)
            elif "-%s" % (filter_key,) in self.request.query_params:
                filter_value = self.request.query_params.get("-%s" % (filter_key,))
                query.must_by_term(key=filter_key, value=filter_value, verify_key=False, include=False)
        if self.has_search_argument:
            query.set_search_term(term=self.search_argument, field="_all")
        return query

    # Properties

    @property
    def filterable_fields(self):
        """
        Get a list of the fields that the Elasticsearch model referenced by this
        view can be filtered on.
        :return: a list of the fields that the Elasticsearch model referenced by
        this view can be filtered on.
        """
        return self.soft_filterable_fields + self.hard_filterable_fields

    @property
    def hard_filterable_fields(self):
        """
        Get a list of strings representing the fields that are explicitly declared on the
        queried Elasticsearch model that can be filtered against.
        :return: a list of strings representing the fields that are explicitly declared on
        the queried Elasticsearch model that can be filtered against.
        """
        return self.queryable_model_fields

    @property
    def has_search_argument(self):
        """
        Get whether or not the request has a search argument.
        :return: whether or not the request has a search argument.
        """
        return settings.SEARCH_PARAM in self.request.query_params

    @property
    def search_argument(self):
        """
        Get the search argument from the request query string.
        :return: the search argument from the request query string.
        """
        if self._search_argument is None:
            self._search_argument = self.request.query_params.get(settings.SEARCH_PARAM, "")
        return self._search_argument

    @property
    def soft_filterable_fields(self):
        """
        Get a list of strings representing the fields that are not explicitly declared on
        the queried Elasticsearch model that can be filtered against.
        :return: A list of strings representing the fields that are not explicitly declared
        on the queried Elasticsearch model that can be filtered against.
        """
        return []

    # Representation and Comparison


class BaseElasticsearchAnalyticsAPIViewMixin(BaseElasticsearchFilterableMappedAPIViewMixin):
    """
    This is a base mixin class for all Web Sight APIView classes that query Elasticsearch to retrieve
    analytical data about models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _apply_aggregates_to_query(self, query):
        """
        Apply the necessary aggregates to the given query and return it.
        :param query: The query to add aggregates to.
        :return: The query with the added aggregates.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _extract_contents_from_response(self, response):
        to_return = {}
        for aggregate_name, aggregate in self.query.aggregates.iteritems():
            to_return[aggregate_name] = aggregate.unpack_response(response.aggregations[aggregate_name])
        return to_return

    def _query_elasticsearch(self):
        es_index = self._get_elasticsearch_index()
        self._query = self.es_query_class(suppress_source=True)
        self._query = self._apply_filters_to_query(self._query)
        self._query = self._apply_aggregates_to_query(self._query)
        return self._query.search(index=es_index)

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseElasticsearchManyMappedAPIViewMixin(BaseElasticsearchFilterableMappedAPIViewMixin):
    """
    This is a base mixin class for all Web Sight APIView classes that query Elasticsearch models that are paired
    with database models and that return multiple instances of the queried model.
    """

    # Class Members

    _current_page = None
    _page_offset = None
    _sort_argument = None
    _export_argument = None
    _exporter_map = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def get(self, *args, **kwargs):
        """
        Handle the HTTP GET request to this APIView.
        :param args: Positional arguments.
        :param kwargs: Keyword arguments.
        :return: A Django rest framework response object.
        """
        if not self.has_export_argument:
            to_return = super(BaseElasticsearchManyMappedAPIViewMixin, self).get(*args, **kwargs)
            to_return.data["sortable_fields"] = self.sortable_fields
            return to_return
        else:
            self.check_ws_permissions()
            query_results = self._query_elasticsearch()
            return self.exporter_map[self.export_argument].get_django_response_from_elasticsearch_response(query_results)

    # Protected Methods

    def _get_elasticsearch_query(self):
        to_return = super(BaseElasticsearchManyMappedAPIViewMixin, self)._get_elasticsearch_query()
        if self.has_export_argument:
            self.__validate_export_value()
            to_return.offset = 0
            to_return.size = config.es_max_query_size
        else:
            to_return.offset = self.page_offset
            to_return.size = self.page_size
        if self.has_sort_argument:
            self.__validate_sort_field()
            to_return.add_sort_field(field_name=self.sort_field, direction=self.sort_direction)
        return to_return

    def _extract_contents_from_response(self, response):
        results = self._extract_objects_from_response(response)
        to_return = PaginationSerializer(
            results=results,
            count=response.results_count,
            current_page=self.current_page,
        )
        return to_return.to_response_dict()

    # Private Methods

    def __get_current_page(self):
        """
        Get an integer representing the current page if a page number was supplied in the request.
        :return: An integer representing the current page if a page number was supplied in the request.
        """
        page_number = self.request.query_params.get(settings.PAGINATION_PARAM, 1)
        to_return = int(page_number) if ValidationHelper.is_int(page_number) else 1
        return max(to_return, 1)

    def __validate_export_value(self):
        """
        Ensure that the value in self.export_argument is a valid string to export via.
        :return: None
        """
        ValidationHelper.validate_in(to_check=self.export_argument, contained_by=self.exporter_map_keys)

    def __validate_sort_field(self):
        """
        Ensure that the field in self.sort_field is a valid field to be sorted upon.
        :return: None
        """
        ValidationHelper.validate_in(to_check=self.sort_field, contained_by=self.sortable_fields)

    # Properties

    @property
    def current_page(self):
        """
        Get the current requested page number
        :return: the current requested page number
        """
        if self._current_page is None:
            self._current_page = self.__get_current_page()
        return self._current_page

    @property
    def export_argument(self):
        """
        Get the export argument from the request's query string.
        :return: the export argument from the request's query string.
        """
        if self._export_argument is None:
            self._export_argument = self.request.query_params.get(settings.EXPORT_PARAM, "")
        return self._export_argument

    @property
    def exporter_map(self):
        """
        Get a dictionary that maps export types to the classes that can handle exporting data to a file
        of the given type.
        :return: A dictionary that maps export types to the classes that can handle exporting data to a file
        of the given type.
        """
        if self._exporter_map is None:
            self._exporter_map = get_export_type_wrapper_map()
        return self._exporter_map

    @property
    def exporter_map_keys(self):
        """
        Get a list of strings representing the valid export types supported by Web Sight.
        :return: a list of strings representing the valid export types supported by Web Sight.
        """
        return self.exporter_map.keys()

    @property
    def has_export_argument(self):
        """
        Get whether or not the request has an export argument.
        :return: whether or not the request has an export argument.
        """
        return settings.EXPORT_PARAM in self.request.query_params

    @property
    def has_sort_argument(self):
        """
        Get whether or not the request has a sorting argument.
        :return: whether or not the request has a sorting argument.
        """
        return api_settings.ORDERING_PARAM in self.request.query_params

    @property
    def page_offset(self):
        """
        Get the page offset to use when querying Elasticsearch.
        :return: the page offset to use when querying Elasticsearch.
        """
        if self._page_offset is None:
            self._page_offset = (self.current_page - 1) * self.page_size
        return self._page_offset

    @property
    def page_size(self):
        """
        Get the page size to use.
        :return: the page size to use.
        """
        return api_settings.PAGE_SIZE

    @property
    def sortable_fields(self):
        """
        Get a list of the fields that this query allows sorting on.
        :return: a list of the fields that this query allows sorting on.
        """
        return self.queryable_model_fields

    @property
    def sort_argument(self):
        """
        Get the sort argument from the request query string.
        :return: the sort argument from the request query string.
        """
        if self._sort_argument is None:
            self._sort_argument = self.request.query_params.get(api_settings.ORDERING_PARAM, "")
        return self._sort_argument

    @property
    def sort_direction(self):
        """
        Get a string representing the direction that results should be ordered in.
        :return: a string representing the direction that results should be ordered in.
        """
        to_return = "desc" if self.sort_argument.startswith("-") else "asc"
        print("SORT DIRECTION IS %s" % (to_return,))
        return to_return

    @property
    def sort_field(self):
        """
        Get the field to sort query results on.
        :return: The field to sort query results on.
        """
        return self.sort_argument[1:] if self.sort_argument.startswith("-") else self.sort_argument

    # Representation and Comparison


class BaseElasticsearchRelatedAPIViewMixin(BaseElasticsearchManyMappedAPIViewMixin):
    """
    This is a base Elasticsearch APIView mixin that allows users to query data based on multidoc queries
    that span multiple document types.
    """

    # Class Members

    _filter_by_parent_db_object = False

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def _apply_filters_to_query(self, query):
        query = super(BaseElasticsearchRelatedAPIViewMixin, self)._apply_filters_to_query(query)
        filter_value = self._get_related_filter_value()
        if filter_value is None:
            raise ObjectDoesNotExist()
        query.must_by_term(key=self.related_filter_key, value=filter_value)
        return query

    def _get_related_filter_value(self):
        """
        Get the value that the Elasticsearch query should filter on to ensure results are related
        to the relevant document.
        :return: The value that the Elasticsearch query should filter on to ensure results are related
        to the relevant document. If this method returns None, then a 404 will be raised.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def queryable_model_fields(self):
        return self.es_query_class.get_queryable_fields()

    @property
    def related_filter_key(self):
        """
        Get the key that the Elasticsearch query should be filtered on to ensure results are related to the
        relevant document.
        :return: the key that the Elasticsearch query should be filtered on to ensure results are related
        to the relevant document.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Representation and Comparison


class BaseEsMixin(object):
    """
    This is a base class for Elasticsearch mixin classes.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_es_query_class(cls):
        """
        Get the Elasticsearch query class that this APIView is meant to query.
        :return: The Elasticsearch query class that this APIView is meant to query.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseRelatedEsMixin(BaseEsMixin):
    """
    This is a base class for Elasticsearch mixin classes that rely on multidoc queries.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_related_es_query_class(cls):
        """
        Get the Elasticsearch query class that this related Elasticsearch mixin will retrieve
        data from.
        :return: The Elasticsearch query class that this related Elasticsearch mixin will retrieve
        data from.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    # Protected Methods

    def _apply_related_elasticsearch_query_filters(self, query):
        """
        Apply filters to the given query to restrict results to only those that match the Elasticsearch
        document that is related to data returned by this APIView.
        :param query: The query to apply filters to.
        :return: The query with filters applied.
        """
        query.must_by_term(key=self.mapped_elasticsearch_key, value=self.mapped_elasticsearch_value)
        return query

    def _get_related_filter_value(self):
        """
        Get the value that the Elasticsearch query should filter on to ensure results are related
        to the relevant document.
        :return: The value that the Elasticsearch query should filter on to ensure results are related
        to the relevant document. If this method returns None, then a 404 will be raised.
        """
        query = self.related_elasticsearch_query_class()
        query = self._apply_related_elasticsearch_query_filters(query)
        query.queryable_model_fields = [self.parent_related_value_key]
        result = query.search(self._get_elasticsearch_index())
        if result.results_count == 0:
            return None
        if result.results_count > 0:
            logger.warning(
                "Too many results returned in APIView %s (%s returned)."
                % (self.__class__.__name__, result.results_count)
            )
        return result.results[0]["_source"][self.parent_related_value_key]

    # Private Methods

    # Properties

    @property
    def parent_related_value_key(self):
        """
        Get a string representing the key contained in the parent Elasticsearch document that the relationship
        should be based upon.
        :return: a string representing the key contained in the parent Elasticsearch document that the
        relationship should be based upon.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def related_filter_key(self):
        """
        Get the key that the Elasticsearch query should be filtered on to ensure results are related to the
        relevant document.
        :return: the key that the Elasticsearch query should be filtered on to ensure results are related
        to the relevant document.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def related_elasticsearch_query_class(self):
        """
        Get the Elasticsearch query class that this related Elasticsearch mixin will retrieve
        data from.
        :return: The Elasticsearch query class that this related Elasticsearch mixin will retrieve
        data from.
        """
        return self.__class__.get_related_es_query_class()

    # Representation and Comparison


class BaseDbMixin(object):
    """
    This is a base class for database mixin classes.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_db_model_class(cls):
        """
        Get the database model class that this APIView is meant to query against.
        :return: The database model class that this APIView is meant to query against.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    # Protected Methods

    def _apply_filters_to_query(self, query):
        query = super(BaseDbMixin, self)._apply_filters_to_query(query)
        if self.filter_by_parent_db_object:
            return self._apply_parent_db_object_filter(query)
        else:
            return query

    def _apply_parent_db_object_filter(self, query):
        """
        Apply a filter to the given Elasticsearch query that restricts results to only those objects
        that are related to the parent database object.
        :param query: The query to apply filters to.
        :return: The query with filters applied.
        """
        query.must_by_term(key=self.mapped_elasticsearch_key, value=self.mapped_elasticsearch_value)
        return query

    def _check_db_object_permissions(self):
        """
        Check to see if the requesting user has sufficient permissions to be querying self.db_object.
        :return: True if the requesting user has sufficient permissions to be querying self.db_object, False
        otherwise.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _get_elasticsearch_index(self):
        """
        Get the Elasticsearch index that the resulting Elasticsearch query should be restricted to.
        :return: The Elasticsearch index that the resulting Elasticsearch query should be restricted to.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    # Properties

    @property
    def mapped_elasticsearch_key(self):
        """
        Get a string representing the key that the Elasticsearch query should be filtered by when filtering
        upon a parent database object.
        :return: a string representing the key that the Elasticsearch query should be filtered by when
        filtering upon a parent database object.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def mapped_elasticsearch_value(self):
        """
        Get a string representing the value that the Elasticsearch query should be filtered upon when filtering
        upon a parent database object.
        :return: a string representing the value that the Elasticsearch query should be filtered upon when
        filtering upon a parent database object.
        """
        return self.db_object.uuid

    # Representation and Comparison
