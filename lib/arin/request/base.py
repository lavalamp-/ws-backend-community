# -*- coding: utf-8 -*-
from __future__ import absolute_import

from urlparse import urljoin
import requests

from ..constants import ArinConstants
from lib.wscache import redis_cache


class BaseArinRequest(object):
    """
    This is a base class for representing an HTTP request sent to the ARIN WHOIS RWS API.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_full_url(cls):
        """
        Get a string representing the full URL that this class will send requests to.
        :return: A string representing the full URL that this class will send requests to.
        """
        return urljoin(ArinConstants.API_BASE_URL, cls.get_url_path())

    @classmethod
    def get_response_class(cls):
        """
        Get the response class that this request class should use to wrap responses from the ARIN API.
        :return: The response class that this request class should use to wrap responses from the ARIN API.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @classmethod
    def get_url_path(cls):
        """
        Get a string representing the URL path that the resource represented by this request class resides
        at.
        :return: A string representing the URL path that the resource represented by this request class resides
        at.
        """
        raise NotImplementedError("Subclasses must implememt this!")

    # Public Methods

    @redis_cache
    def send(self, url, *args, **kwargs):
        """
        Send a request to the remote ARIN endpoint and return a the wrapped response.
        :param url: The URL to send a request to.
        :param args: Positional arguments to pass to requests.get.
        :param kwargs: Keyword arguments to pass to requests.get.
        :return: An ARIN response object wrapping the response returned by the ARIN WHOIS RWS API.
        """
        if "headers" not in kwargs:
            kwargs["headers"] = {}
        kwargs["headers"]["Accept"] = "application/json"
        to_return = requests.get(url, *args, **kwargs)
        return self.response_class(to_return)

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def full_url(self):
        """
        Get the full URL path to the resource that this class is built to query.
        :return: the full URL path to the resource that this class is built to query.
        """
        return self.__class__.get_full_url()

    @property
    def response_class(self):
        """
        Get the response class that this request class uses to wrap responses returned by the ARIN API.
        :return: the response class that this request class uses to wrap responses returned by the ARIN API.
        """
        return self.__class__.get_response_class()

    @property
    def url_path(self):
        """
        Get the URL path that this request class is configured to send a request to.
        :return: the URL path that this request class is configured to send a request to.
        """
        return self.__class__.get_url_path()

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)


class BaseSingleArinRequest(BaseArinRequest):
    """
    This is a base class for request classes that query single instances of a type of resource.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get(cls, handle, *args, **kwargs):
        """
        Send a request to the ARIN WHOIS API using this class and the given URL path and return a wrapped response.
        :param handle: The handle of the resource to request.
        :param args: Positional arguments to pass to requests.get.
        :param kwargs: Keyword arguments to pass to requests.get.
        :return: An ARIN response object wrapping the response returned by the ARIN WHOIS RWS API.
        """
        request = cls()
        request_url = "%s/%s" % (cls.get_full_url(), handle)
        return request.send(request_url, *args, **kwargs)

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseManyArinRequest(BaseArinRequest):
    """
    This is a base class for request classes that query multiple instances of a type of resource.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get(cls, url, *args, **kwargs):
        """
        Send a request to the ARIN WHOIS API using this class and the given URL path and return a wrapped response.
        :param url: The URL to request.
        :param args: Positional arguments to pass to requests.get.
        :param kwargs: Keyword arguments to pass to requests.get.
        :return: An ARIN response object wrapping the response returned by the ARIN WHOIS RWS API.
        """
        request = cls()
        return request.send(url, *args, **kwargs)

    @classmethod
    def search_by_key(cls, key=None, value=None, wild_before=True, wild_after=True, *args, **kwargs):
        """
        Search for all records related to this request by the given key and the given value.
        :param key: The key to search against.
        :param value: The value to search for.
        :param wild_before: Whether or not to add a wildcard tag before the search value.
        :param wild_after: Whether or not to add a wildcard tag after the search value.
        :param args: Positional arguments to pass to requests.get.
        :param kwargs: Keyword arguments to pass to requests.get.
        :return: An ARIN response object wrapping the response returned by the ARIN WHOIS RWS API.
        """
        search_term = value
        if wild_before:
            search_term = "*%s" % (search_term,)
        if wild_after:
            search_term = "%s*" % (search_term,)
        request_url = "%s;%s=%s" % (cls.get_full_url(), key, search_term)
        return cls.get(request_url, *args, **kwargs)

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
