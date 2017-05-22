# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseElasticsearchAnalysis


class HttpTransactionAnalysis(BaseElasticsearchAnalysis):
    """
    Documentation for HttpTransactionAnalysis.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_analyzed_query_class(cls):
        from wselasticsearch.query import HttpTransactionQuery
        return HttpTransactionQuery

    # Public Methods

    # Protected Methods

    def _apply_aggregates(self):
        self.aggregate_on_term(key="content_type", name="content_types")
        self.aggregate_on_term(key="response_status", name="response_statuses")

    # Private Methods

    # Properties

    # Representation and Comparison
