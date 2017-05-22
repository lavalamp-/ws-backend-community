# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseUserQuery


class UserOrganizationSelectQuery(BaseUserQuery):
    """
    This is an Elasticsearch query class for querying UserOrganizationSelectModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import UserOrganizationSelectModel
        return UserOrganizationSelectModel

    # Public Methods

    def sort_by_selected(self):
        """
        Add a sorting clause to this query that orders results from most recently selected.
        :return: None
        """
        self.add_sort_field(field_name="selected_at", direction="desc")

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
