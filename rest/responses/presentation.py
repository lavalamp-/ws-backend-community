# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import WsBaseResponse


class WsPresentationResponse(WsBaseResponse):
    """
    This is the response used to provide presentation data to API users.
    """

    # Class Members

    # Instantiation

    def __init__(self, fields=None, sortable_fields=None, filter_fields=None, *args, **kwargs):
        super(WsPresentationResponse, self).__init__(*args, **kwargs)
        self.data = {
            "fields": fields,
            "sortable_fields": sortable_fields,
            "filter_fields": filter_fields,
        }

    # Static Methods

    # Class Methods

    @classmethod
    def from_es_api_view(cls, api_view, *args, **kwargs):
        """
        Create and return a WsPresentationResponse based on the contents of the given Django APIView that handles
        retrieving data from Elasticsearch.
        :param api_view: The APIView to parse.
        :param args: Positional arguments for instantiation.
        :param kwargs: Keyword arguments for instantiation.
        :return: The response.
        """
        return cls(
            fields=api_view.queryable_model_fields,
            sortable_fields=api_view.sortable_fields if hasattr(api_view, "sortable_fields") else [],
            filter_fields=api_view.filter_fields if hasattr(api_view, "filter_fields") else [],
            *args,
            **kwargs
        )

    @classmethod
    def from_model_api_view(cls, api_view, *args, **kwargs):
        """
        Create and return a WsPresentationResponse based on the contents of the given Django APIView that
        handles retrieving data from standard Django models.
        :param api_view: The APIView to parse.
        :param args: Positional arguments for instantiation.
        :param kwargs: Keyword arguments for instantiation.
        :return: The response.
        """
        return cls(
            fields=list(api_view.serializer_class.Meta.fields),
            sortable_fields=list(api_view.ordering_fields) if hasattr(api_view, "ordering_fields") else [],
            filter_fields=list(api_view.filter_class.Meta.fields) if hasattr(api_view, "filter_class") else [],
            *args,
            **kwargs
        )

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
