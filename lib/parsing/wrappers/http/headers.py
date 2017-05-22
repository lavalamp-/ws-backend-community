# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseWrapper
from lib import CrawlableMixin


class BaseHttpHeaderWrapper(BaseWrapper):
    """
    This is a base class for all wrapper classes that are meant to process HTTP request and response
    headers.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_header_key(cls):
        """
        Get a string representing the header key that this class is meant to process.
        :return: A string representing the header key that this class is meant to process.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def header_key(self):
        """
        Get the header key for the header that this class is meant to process.
        :return: the header key for the header that this class is meant to process.
        """
        return self.__class__.get_header_key()

    # Representation and Comparison


class LocationHttpHeaderWrapper(BaseHttpHeaderWrapper, CrawlableMixin):
    """
    This is a wrapper class for wrapping an HTTP Location header.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_header_key(cls):
        return "Location"

    # Public Methods

    def _get_url_tuples(self):
        return [("location header", self.wrapped_data)]

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def wrapped_type(self):
        return "HTTP Location Header"

    # Representation and Comparison

