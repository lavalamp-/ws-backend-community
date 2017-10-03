# -*- coding: utf-8 -*-
from __future__ import absolute_import

from base64 import b64encode

from .base import BaseElasticsearchModel
from .types import *
from .mixin import S3Mixin


class MalformedHtmlModel(BaseElasticsearchModel, S3Mixin):
    """
    This is an Elasticsearch model class for keeping track of malformed HTML that caused errors
    during Web Sight's processing.
    """

    # Class Members

    traceback = TextElasticsearchType(
        help_text="The error traceback for the error that parsing the HTML caused.",
    )
    error_message = KeywordElasticsearchType(
        help_text="The error message for the error that parsing the HTML caused.",
    )

    # Instantiation

    def __init__(self, traceback=None, error_message=None):
        super(MalformedHtmlModel, self).__init__()
        self.traceback = b64encode(traceback)
        self.error_message = error_message

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.traceback = WsFaker.get_traceback(base64_encoded=True)
        to_populate.error_message = ", ".join(WsFaker.get_words(count=10))
        to_populate.set_s3_attributes(**WsFaker.get_s3_mixin_dictionary())
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
