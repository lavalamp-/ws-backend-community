# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebServiceScanQuery


class GenericWebResourceQuery(BaseWebServiceScanQuery):
    """
    This is an Elasticsearch query class for querying GenericWebServiceModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import GenericWebResourceModel
        return GenericWebResourceModel


class HtmlWebResourceQuery(BaseWebServiceScanQuery):
    """
    This is an Elasticsearch query class for querying HtmlWebResourceModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import HtmlWebResourceModel
        return HtmlWebResourceModel
