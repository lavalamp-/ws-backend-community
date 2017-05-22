# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebServiceScanQuery


class HttpScreenshotQuery(BaseWebServiceScanQuery):
    """
    This is an Elasticsearch model class for querying HttpScreenshotModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import HttpScreenshotModel
        return HttpScreenshotModel

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
