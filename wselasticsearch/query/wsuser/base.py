# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseMappedElasticsearchQuery


class BaseUserQuery(BaseMappedElasticsearchQuery):
    """
    This is a base Elasticsearch query class for querying models that are mapped to users.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def filter_by_user(self, user_uuid):
        """
        Add a filter to this query class to filter on a user's UUID.
        :param user_uuid: The UUID of the user to filter on.
        :return: None
        """
        self.must_by_term(key="user_uuid", value=user_uuid)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
