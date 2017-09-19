# -*- coding: utf-8 -*-
from __future__ import absolute_import

import copy
from django.conf import settings
from rest_framework import authentication
from rest_framework.exceptions import PermissionDenied, NotAcceptable
from rest_framework.response import Response

import rest.responses
from rest.views.exception import OperationFailed


class BaseElasticsearchAPIViewMixin(object):
    """
    This is a mixin class for all Web Sight APIView classes that query data stored in Elasticsearch.
    """

    # Class Members

    authentication_classes = (authentication.TokenAuthentication,)

    _query = None
    _search_argument = None
    _queried_fields = None

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

    def check_ws_permissions(self):
        """
        Check to see if the requesting user has sufficient permissions to be querying the contents of
        this APIView.
        :return: None
        """
        if not self.request.user.is_superuser:
            if not self._check_permissions():
                raise PermissionDenied()

    def get(self, *args, **kwargs):
        """
        Handle the HTTP GET request to this APIView.
        :param args: Positional arguments.
        :param kwargs: Keyword arguments.
        :return: A Django rest framework response object.
        """
        if self.has_presentation_argument:
            return rest.responses.WsPresentationResponse.from_es_api_view(self)
        else:
            self.check_ws_permissions()
            self._validate_arguments()
            response = self._query_elasticsearch()
            response_body = self._extract_contents_from_response(response)
            return Response(response_body)

    # Protected Methods

    def _apply_filters_to_query(self, query):
        """
        Apply the necessary filters to the given Elasticsearch query and return it.
        :param query: The Elasticsearch query to apply filters to.
        :return: The query with filters applied.
        """
        return query

    def _check_permissions(self):
        """
        Check to see if the requesting user has sufficient permissions to be querying the contents of
        this APIView.
        :return: True if the requesting user has sufficient permissions, False otherwise.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _extract_contents_from_response(self, response):
        """
        Process the contents of the given response and return a list or dictionary that will then
        be returned to the requesting user.
        :param response: The Elasticsearch response to process.
        :return: A list or dictionary to return to the requesting user.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _extract_objects_from_response(self, response):
        """
        Process the contents of the given response and return a list of dictionaries reflecting the data
        contained within the Elasticsearch response.
        :param response: The Elasticsearch response to process.
        :return: A list of dictionaries reflecting the contents of the given Elasticsearch response.
        """
        return [self._get_object_from_result(result) for result in response.results]

    def _get_elasticsearch_index(self):
        """
        Get the Elasticsearch index that the resulting Elasticsearch query should be restricted to.
        :return: The Elasticsearch index that the resulting Elasticsearch query should be restricted to.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _get_elasticsearch_query(self):
        """
        Get the Elasticsearch query object that will be used to query Elasticsearch data. This can
        be overridden to initialize the query in custom ways.
        :return: The Elasticsearch query object that will be used to query Elasticsearch data.
        """
        return self.es_query_class()

    def _get_object_from_result(self, es_result):
        """
        Get a dictionary reflecting the data contained within the given Elasticsearch result object.
        :param es_result: An Elasticsearch result object.
        :return: A dictionary reflecting the data contained within the given Elasticsearch result object.
        """
        to_return = {}
        for queried_field in self.queryable_model_fields:
            if queried_field in es_result["_source"]:
                to_return[queried_field] = es_result["_source"][queried_field]
        to_return["type"] = es_result["_type"]
        return to_return

    def _query_elasticsearch(self):
        """
        Submit a query to Elasticsearch and return the corresponding response.
        :return: The response retrieved from Elasticsearch.
        """
        es_index = self._get_elasticsearch_index()
        self._query = self._get_elasticsearch_query()
        self._query = self._apply_filters_to_query(self._query)
        self._query.queried_fields = self.queried_fields
        return self._query.search(index=es_index)

    def _validate_arguments(self):
        """
        Validate that the arguments supplied to this handler are valid for query execution, and raise a
        ValidationError if they are not.
        :return: None
        """
        pass

    # Private Methods

    def __get_queried_fields(self):
        """
        Get a list of the fields meant to be queried by this APIView. This list will take into account
        fields specified in inclusion and exclusion query string parameters.
        :return: A list of the fields meant to be queried by this APIView.
        """
        if not self.has_exclude_fields_argument and not self.has_include_fields_argument:
            return self.queryable_model_fields
        elif self.has_include_fields_argument:
            fields = []
            included_fields = self.request.query_params[settings.INCLUDE_FIELDS_PARAM]
            for included_field in [x.strip() for x in included_fields.split(",")]:
                if included_field in self.queryable_model_fields:
                    fields.append(included_field)
        elif self.has_exclude_fields_argument:
            fields = copy.copy(self.queryable_model_fields)
            excluded_fields = self.request.query_params[settings.EXCLUDE_FIELDS_PARAM]
            for excluded_field in [x.strip() for x in excluded_fields.split(",")]:
                if excluded_field in fields:
                    fields.remove(excluded_field)
        fields = list(set(fields))
        if len(fields) == 0:
            raise OperationFailed(detail="You must specify at least one valid field to query.")
        return fields

    # Properties

    @property
    def has_exclude_fields_argument(self):
        """
        Get whether or not the request has the exclude fields argument.
        :return: whether or not the request has the exclude fields argument.
        """
        return settings.EXCLUDE_FIELDS_PARAM in self.request.query_params

    @property
    def has_include_fields_argument(self):
        """
        Get whether or not the request has the include fields argument.
        :return: whether or not the request has the include fields argument.
        """
        return settings.INCLUDE_FIELDS_PARAM in self.request.query_params

    @property
    def has_presentation_argument(self):
        """
        Get whether or not the request has the presentation argument.
        :return: whether or not the request has the presentation argument.
        """
        return settings.PRESENTATION_PARAM in self.request.query_params

    @property
    def es_query_class(self):
        """
        Get the Elasticsearch query class that this APIView is meant to query.
        :return: The Elasticsearch query class that this APIView is meant to query.
        """
        return self.__class__.get_es_query_class()

    @property
    def queried_fields(self):
        """
        Get a list containing the Elasticsearch model fields that should be queried by this APIView.
        :return: a list containing the Elasticsearch model fields that should be queried by this APIView.
        """
        if self._queried_fields is None:
            self._queried_fields = self.__get_queried_fields()
        return self._queried_fields

    @property
    def queryable_model_fields(self):
        """
        Get a list of the strings on the queried model to return to the requesting user.
        :return: a list of the strings on the queried model to return to the requesting user.
        """
        return self.es_query_class.get_queryable_fields()

    @property
    def query(self):
        """
        Get the Elasticsearch query that this class is configured to run.
        :return: the Elasticsearch query that this class is configured to run.
        """
        return self._query

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)

