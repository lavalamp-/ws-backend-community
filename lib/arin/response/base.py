# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json


class BaseArinResponse(object):
    """
    This is the base class for all response objects returned by the ARIN WHOIS RWS API.
    """

    # Class Members

    # Instantiation

    def __init__(self, response):
        self._response = response
        self._content = None

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def content(self):
        """
        Get the content of this response as a JSON object.
        :return: the content of this response as a JSON object.
        """
        if self._content is None:
            if self.response.status_code == 200:
                self._content = json.loads(self.response.content)
            else:
                self._content = {}
        return self._content

    @property
    def has_content(self):
        """
        Get whether or not the response contains ARIN API response content.
        :return: whether or not the response contains ARIN API response content.
        """
        return self.response.status_code == 200

    @property
    def response(self):
        """
        Get the Python Requests response that this ARIN response wraps.
        :return: the Python Requests response that this ARIN response wraps.
        """
        return self._response

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s)>" % (self.__class__.__name__, self.response.url, self.response.status_code)


class BaseSingleArinResponse(BaseArinResponse):
    """
    This is the base class for all response objects that return a single instance of a type of resource.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseManyArinResponse(BaseArinResponse):
    """
    This is the base class for all response objects that return multiple instances of a type
    of resource.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
