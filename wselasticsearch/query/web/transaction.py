# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebServiceScanQuery


class HttpTransactionQuery(BaseWebServiceScanQuery):
    """
    This is an Elasticsearch model class for querying HttpTransactionModel objects.
    """
    
    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import HttpTransactionModel
        return HttpTransactionModel

    # Public Methods

    def filter_by_response_status(self, status_code):
        """
        Apply a filter to this query to restrict results to only those results with the
        given status code.
        :param status_code: The status code to restrict results to.
        :return: None
        """
        self.must_by_term(key="response_status", value=status_code)

    def filter_by_not_response_status(self, status_code):
        """
        Apply a filter to this query to restrict results to only those results that do not
        match the given status code.
        :param status_code: The status code to restrict results from.
        :return: None
        """
        self.must_by_term(key="response_status", value=status_code, include=False)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
