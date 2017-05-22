# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchQuery


class AllElasticsearchQuery(BaseElasticsearchQuery):
    """
    This is an Elasticsearch query class that is meant to query all of the document types in
    a given index.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        return None

    # Public Methods

    # Protected Methods

    def _validate_queryable_field(self, field):
        pass

    # Private Methods

    # Properties

    @property
    def doc_type(self):
        return None

    @property
    def queryable_fields(self):
        return []

    # Representation and Comparison
