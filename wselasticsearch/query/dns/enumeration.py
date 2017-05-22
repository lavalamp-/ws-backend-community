# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseDomainNameScanQuery


class SubdomainEnumerationQuery(BaseDomainNameScanQuery):
    """
    This is an Elasticsearch query class for querying SubdomainEnumerationModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import SubdomainEnumerationModel
        return SubdomainEnumerationModel

    def filter_by_enumeration_method(self, method):
        """
        Apply a filter to this query that restricts results to only those results found by
        the given method.
        :param method: The method to filter on.
        :return: None
        """
        self.must_by_term(key="enumeration_method", value=method)

    def filter_by_parent_domain(self, parent_domain):
        """
        Apply a filter to this query that restricts results to only those results for the
        given parent domain.
        :param parent_domain: The parent domain.
        :return: None
        """
        self.must_by_term(key="parent_domain", value=parent_domain)
