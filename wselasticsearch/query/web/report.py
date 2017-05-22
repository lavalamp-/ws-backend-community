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


class WebServiceTechnologiesReportQuery(BaseWebServiceScanQuery):
    """
    This is an Elasticsearch model class for querying WebServiceTechnologyReport objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import WebServiceTechnologiesReportModel
        return WebServiceTechnologiesReportModel

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class WebServiceHeadersReportQuery(BaseWebServiceScanQuery):
    """
    This is an Elasticsearch model class for querying WebServiceHeaderReport objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import WebServiceHeadersReportModel
        return WebServiceHeadersReportModel

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
