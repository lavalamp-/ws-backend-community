# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebServiceScanQuery


class WebServiceReportQuery(BaseWebServiceScanQuery):
    """
    This is an Elasticsearch query class for querying WebServiceReportModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import WebServiceReportModel
        return WebServiceReportModel
