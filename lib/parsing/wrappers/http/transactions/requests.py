# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import HttpTransactionWrapperBase, HttpRequestWrapperBase, HttpResponseWrapperBase


class RequestsTransactionWrapper(HttpTransactionWrapperBase):
    """
    A wrapper class for wrapping an HTTP request and its corresponding response as retrieved
    through the use of the Python requests library.
    """

    # Class Members

    _request_wrapper = None
    _response_wrapper = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def request(self):
        if self._request_wrapper is None:
            self._request_wrapper = RequestsRequestWrapper(self.wrapped_data.request)
        return self._request_wrapper

    @property
    def request_duration(self):
        return self.wrapped_data.elapsed

    @property
    def response(self):
        if self._response_wrapper is None:
            self._response_wrapper = RequestsResponseWrapper(self.wrapped_data)
        return self._response_wrapper

    # Representation and Comparison


class RequestsRequestWrapper(HttpRequestWrapperBase):
    """
    A wrapper class for wrapping an HTTP request as retrieved through the use of the Python
    requests library.
    """

    # Class Members

    _header_tuples = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def headers(self):
        if self._header_tuples is None:
            self._header_tuples = []
            for k, v in self.wrapped_data.headers.iteritems():
                self._header_tuples.append((k, v))
        return self._header_tuples

    @property
    def method_string(self):
        return self.wrapped_data.method

    @property
    def requested_url(self):
        return self.wrapped_data.url

    # Representation and Comparison


class RequestsResponseWrapper(HttpResponseWrapperBase):
    """
    A wrapper class for wrapping an HTTP response as retrieved through the use fo the Python
    requests library.
    """

    # Class Members

    _header_tuples = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def content(self):
        return self.wrapped_data.content

    @property
    def encoding(self):
        return self.wrapped_data.encoding

    @property
    def headers(self):
        if self._header_tuples is None:
            self._header_tuples = []
            for k, v in self.wrapped_data.headers.iteritems():
                self._header_tuples.append((k, v))
        return self._header_tuples

    @property
    def status_code(self):
        return int(self.wrapped_data.status_code)

    # Representation and Comparison
