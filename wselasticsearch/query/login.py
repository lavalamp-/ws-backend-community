# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchQuery


class LoginAttemptQuery(BaseElasticsearchQuery):
    """
    A query class for querying SslSupportModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import LoginAttemptModel
        return LoginAttemptModel

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
