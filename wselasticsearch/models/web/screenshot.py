# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebServiceScanModel
from ..mixin import S3Mixin
from ..types import *


class HttpScreenshotModel(BaseWebServiceScanModel, S3Mixin):
    """
    This is an Elasticsearch model class for representing a screenshot taken of a web service's URL.
    """

    # Class Members

    url = KeywordElasticsearchType()

    # Instantiation

    def __init__(self, url=None, **kwargs):
        super(HttpScreenshotModel, self).__init__(**kwargs)
        self.url = url

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.url = WsFaker.get_url()
        to_populate.set_s3_attributes(**WsFaker.get_s3_mixin_dictionary())
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
