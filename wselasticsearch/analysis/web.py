# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchAnalysis
from ..models import HttpScreenshotModel
from ..query.aggregates import TermsAggregate


class WebServiceScanAnalysis(BaseElasticsearchAnalysis):
    """
    This is an analysis class for collecting all of the data retrieved during a single web
    service scan.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_analyzed_query_class(cls):
        from wselasticsearch.query import WebScanMultidocQuery
        return WebScanMultidocQuery

    # Public Methods

    # Protected Methods

    def _apply_aggregates(self):
        self.__apply_screenshot_url_aggregate()

    # Private Methods

    def __apply_screenshot_url_aggregate(self):
        """
        Add an aggregate to this query that will retrieve all screenshot S3 URLs for screenshots
        taken during the given scan.
        :return: None
        """
        new_aggregate = TermsAggregate(field="s3_key", name="screenshot_urls")
        self.query.add_aggregate_for_class(model_class=HttpScreenshotModel, aggregate=new_aggregate)

    # Properties

    # Representation and Comparison
