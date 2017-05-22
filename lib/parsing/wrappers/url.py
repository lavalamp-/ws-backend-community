# -*- coding: utf-8 -*-
from __future__ import absolute_import

import copy

from .base import BaseWrapper
from .exception import InvalidUrlError, UnknownPortError
from lib import ValidationHelper


class UrlWrapper(BaseWrapper):
    """
    This class contains functionality for wrapping a URL string.
    """

    # Class Members

    _authority = None
    _destination = None
    _full_path_string = None
    _password = None
    _path = None
    _path_wrapper = None
    _port = None
    _scheme = None
    _username = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def from_endpoint(cls, hostname=None, port=None, use_ssl=False, path=None):
        """
        Create and return a UrlWrapper object representing the given endpoint.
        :param hostname: The IP address to create a URL from.
        :param port: The port to create a URL from.
        :param use_ssl: Whether or not to use HTTPS.
        :param path: The path to apply to the URL.
        :return: A UrlWrapper object representing the contents of the method arguments.
        """
        if path is None:
            path = "/"
        elif not path.startswith("/"):
            path = "/%s" % (path,)
        if use_ssl and port == 443:
            url_string = "https://%s%s" % (hostname, path)
        elif not use_ssl and port == 80:
            url_string = "http://%s%s" % (hostname, path)
        else:
            url_string = "%s://%s:%s%s" % ("https" if use_ssl else "http", hostname, port, path)
        return UrlWrapper(url_string)

    # Public Methods

    def has_same_origin(
            self,
            url_wrapper=None,
            url_string=None,
            include_protocol=True,
            include_host=True,
            include_port=True,
    ):
        """
        Check to see whether or not this UrlWrapper's URL has the same origin as another URL.
        :param url_wrapper: A UrlWrapper to check against. Note that only this value or url_string should be
        supplied - supplying both is not supported.
        :param url_string: A string containing a URL to check against.  Note that only this value or
        url_wrapper should be supplied - supplying both is not supported.
        :param include_protocol: Whether or not to include the URL protocol in the check.
        :param include_host: Whether or not to include the URL host in the check.
        :param include_port: Whether or not to include the URL port in the check.
        :return: True if the given URL has the same origin as this one, otherwise False.
        """
        if url_string:
            url_wrapper = UrlWrapper(url_string)
        checks = []
        if include_protocol:
            checks.append(self.scheme == url_wrapper.scheme)
        if include_host:
            checks.append(self.destination == url_wrapper.destination)
        if include_port:
            checks.append(self.port == url_wrapper.port)
        return all(checks)

    def resolve_against(self, path, as_string=False):
        """
        Take the given path, resolve it against the path that this URL wrapper contains,
        and return a new UrlWrapper object with the resolved path.
        :param path: The path to resolve.
        :param as_string: If True, return the string representation of the newly-created
        URL. Otherwise return a UrlWrapper object.
        :return: A new UrlWrapper wrapping the URL that represents this wrapper with
        the resolved path of path unless as_string is True, then just return the string
        version of the new UrlWrapper.
        """
        to_return = copy.deepcopy(self)
        if "?" in path:
            after = path[path.find("?"):]
            path = path[:path.find("?")]
        elif "#" in path:
            after = path[path.find("#"):]
            path = path[:path.find("#")]
        else:
            after = ""
        to_return.path_wrapper.resolve_against(path)
        new_path = to_return.path
        to_return._path_wrapper = UrlPathWrapper("%s%s" % (new_path, after))
        if as_string:
            return to_return.to_string()
        else:
            return to_return

    def to_string(self):
        """
        Get a string representing this URL.
        :return: A string representing this URL.
        """
        url = "%s://%s" % ("http" if self.is_http_scheme else "https", self.authority)
        url_with_path = "%s%s" % (url, self.path_wrapper.to_string())
        return url_with_path

    # Protected Methods

    def _process_data(self):
        to_process = self.wrapped_data
        if ":" not in to_process:
            raise InvalidUrlError("No : found in URL (%s)." % (to_process,))
        self._scheme = to_process[:to_process.find(":")]
        to_process = to_process[to_process.find(":")+1:]
        if not to_process.startswith("//"):
            raise InvalidUrlError(
                "No trailing double slashes found after URL scheme (%s)."
                % (self.wrapped_data,)
            )
        to_process = to_process[2:]
        first_slash = to_process.find("/")
        first_question = to_process.find("?")
        first_hash = to_process.find("#")
        encounters = [first_slash, first_question, first_hash]
        if all([x == -1 for x in encounters]):
            self._authority = to_process
            to_process = ""
        else:
            encounters = filter(lambda x: x > -1, encounters)
            first_encounter = min(encounters)
            self._authority = to_process[:first_encounter]
            to_process = to_process[first_encounter:]
        if "@" in self.authority:
            user_pass = self.authority[:self.authority.find("@")]
            if ":" not in user_pass:
                raise InvalidUrlError(
                    "Credentials supplied in URL, but no colon was found delimiting them (%s)."
                    % (self.wrapped_data,)
                )
            self._username = user_pass[:user_pass.find(":")]
            self._password = user_pass[user_pass.find(":")+1:]
            rest_of_authority = self.authority[self.authority.find("@") + 1:]
        else:
            rest_of_authority = self.authority
        if ":" in rest_of_authority:
            self._destination = rest_of_authority[:rest_of_authority.find(":")]
            port = rest_of_authority[rest_of_authority.find(":")+1:]
            ValidationHelper.validate_port(port)
            self._port = int(port)
        else:
            self._destination = rest_of_authority
        self._full_path_string = to_process

    # Private Methods

    # Properties

    @property
    def authority(self):
        """
        Get the URL authority.
        :return: the URL authority.
        """
        return self._authority

    @property
    def destination(self):
        """
        Get the remote destination address in the URL.
        :return: the remote destination address in the URL.
        """
        return self._destination

    @property
    def fragment(self):
        """
        Get the URL fragment found in the URL.
        :return: the URL fragment found in the URL.
        """
        return self.path_wrapper.fragment

    @property
    def full_path_string(self):
        """
        Get the full path string for the URL (everything after authority).
        :return: the full path string for the URL (everything after authority).
        """
        return self._full_path_string

    @property
    def is_https_scheme(self):
        """
        Get whether or not self.scheme is the HTTPS protocol.
        :return: whether or not self.scheme is the HTTPS protocol.
        """
        return self.scheme == "https"

    @property
    def is_http_scheme(self):
        """
        Get whether or not self.scheme is the HTTP protocol.
        :return: whether or not self.scheme is the HTTP protocol.
        """
        return self.scheme == "http"

    @property
    def is_web_url(self):
        """
        Get whether or not the wrapped URL is used to access a service over HTTP
        or HTTPS.
        :return: whether or not the wrapped URL is used to access a service over
        HTTP or HTTPS.
        """
        return self.is_http_scheme or self.is_https_scheme

    @property
    def password(self):
        """
        Get the password found in the wrapped URL.
        :return: the password found in the wrapped URL.
        """
        return self._password

    @property
    def path(self):
        """
        Get the path found in the URL.
        :return: the path found in the URL.
        """
        return self.path_wrapper.path

    @property
    def path_wrapper(self):
        """
        Get a UrlPathWrapper wrapping the URL's path.
        :return: a UrlPathWrapper wrapping the URL's path.
        """
        if self._path_wrapper is None:
            self._path_wrapper = UrlPathWrapper(self.full_path_string)
        return self._path_wrapper

    @property
    def path_segments(self):
        """
        Get a list of strings representing the path segments found in the URL.
        :return: a list of strings representing the path segments found in the URL.
        """
        return self.path_wrapper.path_segments

    @property
    def port(self):
        """
        Get the port that the URL points to.
        :return: the port that the URL points to.
        """
        if self._port is None:
            if self.is_http_scheme:
                return 80
            elif self.is_https_scheme:
                return 443
            else:
                raise UnknownPortError(
                    "Unsure of what port to return for scheme of %s."
                    % (self.scheme,)
                )
        else:
            return self._port

    @property
    def port_supplied(self):
        """
        Get whether or not a port was explicitly supplied in the wrapped URL.
        :return: whether or not a port was explicitly supplied in the wrapped URL.
        """
        return self._port is not None

    @property
    def query_arguments(self):
        """
        Get a dictionary mapping keys to the values found within the query string wrapper.
        :return: a dictionary mapping keys to the values found within the query string wrapper.
        """
        return self.query_string_wrapper.dictionary

    @property
    def query_string(self):
        """
        Get the query string found in the URL.
        :return: the query string found in the URL.
        """
        return self.path_wrapper.query_string

    @property
    def query_string_dict(self):
        """
        Get a dictionary mapping the keys and values found in self.query_string.
        :return: a dictionary mapping the keys and values found in self.query_string.
        """
        return self.path_wrapper.query_string_dict

    @property
    def query_string_wrapper(self):
        """
        Get a QueryStringWrapper that wraps self.query_string.
        :return: a QueryStringWrapper that wraps self.query_string.
        """
        return self.path_wrapper.query_string_wrapper

    @property
    def resolved_path(self):
        """
        Get the URL path after resolving .. and . from within it.
        :return: the URL path after resolving .. and . from within it.
        """
        return self.path_wrapper.resolved_path

    @property
    def resolved_path_segments(self):
        """
        Get a list of path segments found in the URL after resolving .. and . segments.
        :return: a list of path segments found in the URL after resolving .. and . segments.
        """
        return self.path_wrapper.resolved_path_segments

    @property
    def scheme(self):
        """
        Get the scheme string found in the wrapped URL.
        :return: the scheme string found in the wrapped URL.
        """
        return self._scheme

    @property
    def username(self):
        """
        Get the username found in the wrapped URL.
        :return: the username found in the wrapped URL.
        """
        return self._username

    @property
    def wrapped_type(self):
        return "URL"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self)

    def __str__(self):
        return self.to_string()


class UrlPathWrapper(BaseWrapper):
    """
    Documentation for UrlPathWrapper.
    """

    # Class Members

    _fragment = None
    _path = None
    _path_segments = None
    _query_string = None
    _query_string_wrapper = None
    _resolved_path = None
    _resolved_path_segments = None

    # Instantiation

    def __init__(self, to_wrap=None):
        """
        Initialize this UrlPathWrapper by ensuring that a None value is coerced to an empty string.
        :param to_wrap: The value to wrap.
        """
        if to_wrap is None:
            to_wrap = "/"
        super(UrlPathWrapper, self).__init__(to_wrap)

    # Static Methods

    # Class Methods

    # Public Methods

    def resolve_against(self, to_resolve=None):
        """
        Resolve the given path against self.path and return a new instance of self with
        the resolved path.
        :param to_resolve: The path to resolve.
        :return: A new UrlPathWrapper object representing the resolution of to_resolve
        against the path of
        """
        if to_resolve is None or to_resolve == "":
            return
        new_path = self.__resolve_against_path(to_resolve)
        self.__reset()
        self._wrapped_data = new_path
        self._process_data()

    def to_string(self):
        """
        Get a string representation of this URL path.
        :return: A string representation of this URL path.
        """
        to_return = self.resolved_path
        if not self.query_string_wrapper.is_empty:
            to_return = "%s?%s" % (to_return, self.query_string_wrapper.to_string())
        if self.has_fragment:
            to_return = "%s#%s" % (to_return, self.fragment)
        return to_return

    # Protected Methods

    def _process_data(self):
        to_process = self.wrapped_data
        if to_process.startswith("/"):
            first_question = to_process.find("?")
            first_hash = to_process.find("#")
            encounters = [first_question, first_hash]
            if all([x == -1 for x in encounters]):
                self._path = to_process
                to_process = ""
            else:
                encounters = filter(lambda x: x != -1, encounters)
                first_encounter = min(encounters)
                self._path = to_process[:first_encounter]
                to_process = to_process[first_encounter:]
        if to_process.startswith("?"):
            if "#" in to_process:
                self._query_string = to_process[1:to_process.find("#")]
                to_process = to_process[to_process.find("#"):]
            else:
                self._query_string = to_process[1:]
                to_process = ""
        if to_process.startswith("#"):
            self._fragment = to_process[1:]
        if self._path == "" or self._path is None:
            self._path = "/"

    # Private Methods

    def __get_resolved_path_segments(self):
        """
        Get a list of strings representing the path segments found in
        self.path_segments after taking .. and . into account.
        :return: A list of strings representing the path segments found in
        self.path_segments after taking .. and . into account.
        """
        return self.__resolve_path_segments(
            start_segments=[],
            resolve_segments=self.path_segments,
        )

    def __reset(self):
        """
        Clear all of the contents of the lazily-loaded properties so that they are
        computed again.
        :return: None
        """
        self._path_segments = None
        self._resolved_path_segments = None
        self._resolved_path = None
        self._query_string_wrapper = None
        self._fragment = None
        self._query_string = None
        self._path = None

    def __resolve_against_path(self, to_resolve):
        """
        Process the path in to_resolve and resolve self.path against it.
        :param to_resolve: The path to resolve against.
        :return: A string representing the new path when to_resolve is resolved against
        self.path.
        """
        if to_resolve.startswith("/"):
            return to_resolve
        elif to_resolve == "":
            return self.path
        else:
            encounters = [to_resolve.find("?"), to_resolve.find("#")]
            if all([x == -1 for x in encounters]):
                resolve_path = to_resolve
                resolve_end = ""
            else:
                encounters = filter(lambda x: x != -1, encounters)
                encounter = min(encounters)
                resolve_path = to_resolve[:encounter]
                resolve_end = to_resolve[encounter:]
            to_resolve_segments = resolve_path.strip().split("/")
            start_segments = self.resolved_path_segments if self.is_directory_path else self.resolved_path_segments[:-1]
            path_segments = self.__resolve_path_segments(
                start_segments=start_segments,
                resolve_segments=to_resolve_segments,
            )
            if resolve_path.endswith("/"):
                final_path = "/%s/" % ("/".join(path_segments),)
            else:
                final_path = "/%s" % ("/".join(path_segments),)
            return "%s%s" % (final_path, resolve_end)

    def __resolve_path_segments(self, start_segments=None, resolve_segments=None):
        """
        Parse the URL path segments found in resolve_segments against the segments found
        within start_segments.
        :param start_segments: A list of URL path segments to resolve resolve_segments against.
        :param resolve_segments: A list of URL path segments to resolve.
        :return: A list representing starting with the URL path in start_segments and resolving
        the path in resolve_segments.
        """
        for index, segment in enumerate(resolve_segments):
            if segment == ".":
                pass
            elif segment == "" and index != len(resolve_segments) - 1:
                pass
            elif segment == "..":
                if len(start_segments) > 0:
                    start_segments.pop()
            else:
                start_segments.append(segment)
        return start_segments

    # Properties

    @property
    def has_fragment(self):
        """
        Get whether or not this URL path has a URL fragment.
        :return: whether or not this URL path has a URL fragment.
        """
        return self.fragment is not None and self.fragment != ""

    @property
    def is_directory_path(self):
        """
        Get whether or not this path points to a directory.
        :return: whether or not this path points to a directory.
        """
        return self.resolved_path.endswith("/")

    @property
    def is_file_path(self):
        """
        Get whether or not this path points to a file.
        :return: whether or not this path points to a file.
        """
        return not self.is_directory_path

    @property
    def fragment(self):
        """
        Get the URL fragment found in the URL.
        :return: the URL fragment found in the URL.
        """
        return self._fragment

    @property
    def path(self):
        """
        Get the path found in self.wrapped_data.
        :return: the path found in self.wrapped_data.
        """
        return self._path

    @property
    def path_segments(self):
        """
        Get a list of strings representing the path segments found in the URL.
        :return: a list of strings representing the path segments found in the URL.
        """
        if self._path_segments is None:
            if self._path is None or self._path == "/":
                self._path_segments = []
            else:
                self._path_segments = self._path.split("/")[1:]
        return self._path_segments

    @property
    def query_string(self):
        """
        Get the query string found in the URL.
        :return: the query string found in the URL.
        """
        return self._query_string

    @property
    def query_string_dict(self):
        """
        Get a dictionary mapping the keys and values found in self.query_string.
        :return: a dictionary mapping the keys and values found in self.query_string.
        """
        return self.query_string_wrapper.dictionary

    @property
    def query_string_wrapper(self):
        """
        Get a QueryStringWrapper that wraps self.query_string.
        :return: a QueryStringWrapper that wraps self.query_string.
        """
        if self._query_string_wrapper is None:
            self._query_string_wrapper = QueryStringWrapper(self.query_string)
        return self._query_string_wrapper

    @property
    def resolved_path(self):
        """
        Get the URL path after resolving .. and . from within it.
        :return: the URL path after resolving .. and . from within it.
        """
        if self._resolved_path is None:
            if len(self.resolved_path_segments) == 0:
                self._resolved_path = "/"
            else:
                self._resolved_path = "/%s" % ("/".join(self.resolved_path_segments),)
        return self._resolved_path

    @property
    def resolved_path_segments(self):
        """
        Get a list of path segments found in the URL after resolving .. and . segments.
        :return: a list of path segments found in the URL after resolving .. and . segments.
        """
        if self._resolved_path_segments is None:
            self._resolved_path_segments = self.__get_resolved_path_segments()
        return self._resolved_path_segments

    @property
    def wrapped_type(self):
        return "URL path"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self)

    def __str__(self):
        return self.to_string()


class QueryStringWrapper(BaseWrapper):
    """
    Documentation for QueryStringWrapper.
    """

    # Class Members

    _dictionary = None
    _argument_tuples = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def add_argument(self, key=None, value=None):
        """
        Add an argument to this query string.
        :param key: The argument key.
        :param value: The argument value.
        :return: None
        """
        if self._dictionary is None:
            self._dictionary = self.__parse_query_string(self.wrapped_data)
        self._dictionary[key] = value

    def to_string(self):
        """
        Get a string representation of this query string as would be expected in a
        URL.
        :return: A string representation of this query string as would be expected in a
        URL.
        """
        if self.is_empty:
            return ""
        qs_segments = []
        for key, value in self.argument_tuples:
            if value is None:
                qs_segments.append(key)
            else:
                qs_segments.append("%s=%s" % (key, value))
        return "&".join(qs_segments)

    # Protected Methods

    # Private Methods

    def __add_key_value_pair_to_qs_dict(self, key=None, value=None, qs_dict=None):
        """
        Add the given key-value pair to the given query string dictionary. This will
        automatically convert values to lists when multiple values are added for the same key.
        :param key: The key to add.
        :param value: The value to add.
        :param qs_dict: The dictionary to add the key and value to.
        :return: qs_dict with the key-value pair added.
        """
        if key in qs_dict:
            if not isinstance(qs_dict[key], list):
                qs_dict[key] = list(qs_dict[key])
            qs_dict[key].append(value)
        else:
            qs_dict[key] = value
        return qs_dict

    def __get_query_string_tuples(self):
        """
        Get a list of tuples representing the arguments currently contained within this query string.
        :return: a list of tuples representing the arguments currently contained within this query string.
        """
        if self.is_empty:
            return []
        qs_tuples = []
        for k, v in self.dictionary.iteritems():
            if isinstance(v, list):
                for index, value in enumerate(v):
                    qs_tuples.append(("%s[%s]" % (k, index), value))
            elif isinstance(v, dict):
                for dict_key, dict_value in v.iteritems():
                    qs_tuples.append(("%s[%s]" % (k, dict_key), dict_value))
            else:
                qs_tuples.append((k, v))
        return qs_tuples

    def __parse_query_string(self, to_parse):
        """
        Parse the contents of to_parse and return a dictionary mapping keys
        found in the string to their corresponding values.
        :param to_parse: The string to parse.
        :return: a dictionary mapping keys found in the string to their corresponding values.
        """
        if to_parse is None or to_parse == "":
            return {}
        else:
            to_return = {}
            for segment in to_parse.split("&"):
                if "=" in segment:
                    key = segment[:segment.find("=")]
                    value = segment[segment.find("=")+1:]
                else:
                    key = segment
                    value = None
                to_return = self.__add_key_value_pair_to_qs_dict(
                    key=key,
                    value=value,
                    qs_dict=to_return,
                )
            return to_return

    # Properties

    @property
    def argument_tuples(self):
        """
        Get a list of tuples representing the arguments currently contained within this query string.
        :return: a list of tuples representing the arguments currently contained within this query string.
        """
        if self._argument_tuples is None:
            self._argument_tuples = self.__get_query_string_tuples()
        return self._argument_tuples

    @property
    def dictionary(self):
        """
        Get a dictionary mapping the keys to the values in self.wrapped_data.
        :return: a dictionary mapping the keys to the values in self.wrapped_data.
        """
        if self._dictionary is None:
            self._dictionary = self.__parse_query_string(self.wrapped_data)
        return self._dictionary

    @property
    def is_empty(self):
        """
        Get whether or not this query string wrapper contains any data.
        :return: whether or not this query string wrapper contains any data.
        """
        return len(self.dictionary.keys()) == 0

    @property
    def wrapped_type(self):
        return "query string"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self)

    def __str__(self):
        return self.to_string()
