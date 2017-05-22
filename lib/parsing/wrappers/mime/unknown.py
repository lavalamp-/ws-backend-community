# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseDataTypeWrapper


class UnknownWrapper(BaseDataTypeWrapper):
    """
    This is a wrapper class for wrapping content that has an unknown MIME type.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @classmethod
    def get_mime_type(cls):
        return "unknown"

    @property
    def wrapped_type(self):
        return "Unknown Content Type"

    # Representation and Comparison

