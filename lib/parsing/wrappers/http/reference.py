# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import WsIntrospectionHelper
from ..base import BaseWrapper
from .exception import InvalidReferenceError
from ..url import UrlWrapper


def get_header_wrapper_map():
    """
    Get a dictionary that maps HTTP header keys to the wrapper classes meant to parse the contents
    of the given header.
    :return: A dictionary that maps HTTP header keys to the wrapper classes meant to parse the contents
    of the given header.
    """
    wrapper_tuples = WsIntrospectionHelper.get_http_header_wrapper_classes()
    return {wrapper_class.get_header_key(): wrapper_class for class_name, wrapper_class in wrapper_tuples}


class HttpReferenceWrapper(BaseWrapper):
    """
    This is a wrapper for a URL reference found in a crawled document.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        super(HttpReferenceWrapper, self).__init__(*args, **kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    def to_url_wrapper(self):
        """
        Create and return a UrlWrapper containing the contents of this HttpReferenceWrapper if this
        wrapper contains a URL.
        :return: A UrlWrapper containing the contents of this HttpReferenceWrapper if this
        wrapper contains a URL.
        """
        if not self.has_protocol:
            raise InvalidReferenceError(
                "Cannot create a UrlWrapper with the contents of %s."
                % (self.wrapped_data,)
            )
        return UrlWrapper(self.wrapped_data)

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def has_http_protocol(self):
        """
        Get whether or not this URL reference contains a protocol related to HTTP.
        :return: whether or not this URL reference contains a protocol related to HTTP.
        """
        return self.is_http or self.is_https

    @property
    def has_protocol(self):
        """
        Get whether or not this URL reference contains a protocol.
        :return: whether or not this URL reference contains a protocol.
        """
        from lib import RegexLib
        return RegexLib.url_protocol_regex.match(self.wrapped_data)

    @property
    def is_absolute(self):
        """
        Get whether or not this URL reference contains an absolute URL path.
        :return: whether or not this URL reference contains an absolute URL path.
        """
        return not self.is_same_protocol and self.wrapped_data.startswith("/")

    @property
    def is_data(self):
        """
        Get whether or not this URL reference is a data URI.
        :return: whether or not this URL reference is a data URI.
        """
        return self.wrapped_data.startswith("data:")

    @property
    def is_file(self):
        """
        Get whether or not this URL reference is a file URI.
        :return: whether or not this URL reference is a file URI.
        """
        return self.wrapped_data.startswith("file:")

    @property
    def is_http(self):
        """
        Get whether or not this URL reference points to an HTTP endpoint.
        :return: whether or not this URL reference points to an HTTP endpoint.
        """
        return self.wrapped_data.startswith("http:")

    @property
    def is_https(self):
        """
        Get whether or not this URL reference points to an HTTPS endpoint.
        :return: whether or not this URL reference points to an HTTPS endpoint.
        """
        return self.wrapped_data.startswith("https:")

    @property
    def is_http_reference(self):
        """
        Get whether or not this URL reference points to another HTTP or HTTPS resource.
        :return: whether or not this URL reference points to another HTTP or HTTPS resource.
        """
        return not self.is_url_fragment and (
            self.is_http
            or self.is_https
            or self.is_absolute
            or self.is_relative
            or self.is_same_protocol
        )

    @property
    def is_javascript(self):
        """
        Get whether or not this URL reference is a Javascript URI.
        :return: whether or not this URL reference is a Javascript URI.
        """
        return self.wrapped_data.startswith("javascript:")

    @property
    def is_path(self):
        """
        Get whether or not this URL reference contains a path.
        :return: whether or not this URL reference contains a path.
        """
        return self.is_relative or self.is_absolute

    @property
    def is_protocol_url(self):
        """
        Get whether or not this URL reference is a URL that contains a protocol.
        :return: whether or not this URL reference is a URL that contains a protocol.
        """
        return not self.is_uri and self.has_protocol

    @property
    def is_relative(self):
        """
        Get whether or not this URL reference contains a relative URL path.
        :return: whether or not this URL reference contains a relative URL path.
        """
        return not self.has_protocol and not self.is_same_protocol and not self.is_absolute and not self.is_url_fragment

    @property
    def is_same_protocol(self):
        """
        Get whether or not this URL reference points to an endpoint that matches the
        protocol of the request where the reference was taken from.
        :return: whether or not this URL reference points to an endpoint that matches
        the protocol of the request where the reference was taken from.
        """
        return self.wrapped_data.startswith("//")

    @property
    def is_uri(self):
        """
        Get whether or not this URL reference contains a URI.
        :return: whether or not this URL reference contains a URI.
        """
        return self.is_data or self.is_javascript or self.is_file

    @property
    def is_url_fragment(self):
        """
        Get whether or not this URL reference contains a URL fragment.
        :return: whether or not this URL reference contains a URL fragment.
        """
        return self.wrapped_data.startswith("#")

    @property
    def wrapped_type(self):
        return "HTTP reference"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s)>" % (
            self.__class__.__name__,
            self.wrapped_type,
            self.wrapped_data,
        )
