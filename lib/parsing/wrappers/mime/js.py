# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseDataTypeWrapper


class JavaScriptWrapper(BaseDataTypeWrapper):
    """
    A wrapper class for wrapping JavaScript contents.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_mime_type(cls):
        return "javascript"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def wrapped_type(self):
        return "JavaScript"

    # Representation and Comparison


class JavaScriptElementWrapper(JavaScriptWrapper):
    """
    A wrapper class for wrapping the contents of a JavaScript HTML <script> tag.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def wrapped_type(self):
        return "JavaScript HTML Tag"

    # Representation and Comparison
