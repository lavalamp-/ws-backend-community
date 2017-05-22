# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from lib import ElasticsearchableMixin, ConfigManager, ScrapyItemizableMixin, CrawlableMixin
from ...base import BaseWrapper
from ...mime import get_data_type_wrapper_map, UnknownWrapper
from ...mime.base import BaseMarkupWrapper
from ...mime.exception import InvalidMimeStringError

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


class HttpTransactionWrapperBase(
    BaseWrapper,
    ElasticsearchableMixin,
    ScrapyItemizableMixin,
    CrawlableMixin,
):
    """
    This class serves as a wrapper interface for all HTTP transactions (ie: a combination
    of an HTTP request and its response). This class should be subclassed for every format
    that HTTP transactions will be processed as by Web Sight.
    """

    # Class Members

    _crawlable_response_headers = None
    _header_wrapper_map = None
    _requested_url_wrapper = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import VirtualHostFingerprintModel
        return VirtualHostFingerprintModel

    # Public Methods

    def get_scrapy_item_class(self):
        return self.response_content_wrapper.get_scrapy_item_class()

    def get_scrapy_item_kwargs(self):
        to_return = self.response_content_wrapper.get_scrapy_item_kwargs()
        to_return.update({
            "url_path": self.requested_full_url_path,
            "request_headers": self.header_tuples_to_es_representation(self.request.headers),
            "request_method": self.request_verb,
            "response_headers": self.header_tuples_to_es_representation(self.response.headers),
            "query_arguments": self.get_query_string_es_data(),
            "body_arguments": None,
            "response_status": self.response_status_code,
            "content_type": self.response.content_mime_string,
            "content_length": self.response_content_length,
        })
        return to_return

    def get_web_resource_model(self, web_service_scan=None, site_url=None):
        """
        Create a web resource Elasticsearch model based on the contents of this transaction wrapper.
        :param web_service_scan: The web service scan that the result should be associated with.
        :param site_url: The URL of the site where the resource was retrieved from.
        :return: An Elasticsearch model instance representing the contents of this object.
        """
        from lib.inspection import HtmlWebResourceItem
        from lib.parsing import UrlWrapper
        scrapy_item = self.get_scrapy_item()
        if isinstance(scrapy_item, HtmlWebResourceItem):
            if not isinstance(site_url, UrlWrapper):
                site_url = UrlWrapper(site_url)
            return scrapy_item.to_es_model(model=web_service_scan, site_url=site_url)
        else:
            return scrapy_item.to_es_model(model=web_service_scan)

    def header_tuples_to_es_representation(self, header_tuples):
        """
        Convert the contents of the given list of header tuples into a list of dictionaries usable by
        Elasticsearch.
        :param header_tuples: A list of tuples containing header keys and values.
        :return: The contents of the given list of header tuples as a list of dictionaries consumable by
        Elasticsearch.
        """
        to_return = []
        for header_key, header_value in header_tuples:
            to_return.append({
                "key": header_key,
                "value": header_value,
            })
        return to_return

    def get_query_string_es_data(self):
        """
        Get a list of dictionaries containing data about the variables found in the query string that can
        be ingested by Elasticsearch.
        :return: A list of dictionaries containing data about the variables found in the query string that can
        be ingested by Elasticsearch.
        """
        to_return = []
        for k, v in self.requested_url_wrapper.query_arguments.iteritems():
            to_return.append({"key": k, "value": v})
        return to_return

    # Protected Methods

    def _get_url_tuples(self):
        to_return = []
        for crawlable_header in self.crawlable_response_headers:
            to_return.extend(crawlable_header._get_url_tuples())
        if isinstance(self.response_content_wrapper, CrawlableMixin) and self.response_content_length > 0:
            to_return.extend(self.response_content_wrapper._get_url_tuples())
        return to_return

    def _to_es_model(self):
        from wselasticsearch.models import VirtualHostFingerprintModel
        if isinstance(self.response_content_wrapper, BaseMarkupWrapper):
            secondary_hash = self.response_content_wrapper.full_decomposition
        else:
            secondary_hash = self.response_content_hash
        return VirtualHostFingerprintModel(
            response_code=self.response_status_code,
            response_has_content=self.response_has_content,
            response_mime_type=self.response_mime_type,
            response_primary_hash=self.response_content_hash,
            response_secondary_hash=secondary_hash,
            over_ssl=self.is_https,
            hostname=self.requested_host,
        )

    # Private Methods

    # Properties

    @property
    def crawlable_response_headers(self):
        """
        Get a list of response header wrappers that wrap response headers found in this
        transaction and that also inherit from CrawlableMixin.
        :return: a list of response header wrappers that wrap response headers found in
        this transaction and that also inherit from CrawlableMixin.
        """
        if self._crawlable_response_headers is None:
            crawlable_headers = []
            for k, v in self.response.headers:
                if k not in self.header_wrapper_map:
                    continue
                wrapper_class = self.header_wrapper_map[k]
                if issubclass(wrapper_class, CrawlableMixin):
                    crawlable_headers.append(wrapper_class(v))
            self._crawlable_response_headers = crawlable_headers
        return self._crawlable_response_headers

    @property
    def header_wrapper_map(self):
        """
        Get a dictionary that maps HTTP header keys to the wrapper classes meant to parse the contents
        of headers of the given type.
        :return: a dictionary that maps HTTP header keys to the wrapper classes meant to parse the
        contents of headers of the given type.
        """
        if self._header_wrapper_map is None:
            from lib.parsing import get_header_wrapper_map
            self._header_wrapper_map = get_header_wrapper_map()
        return self._header_wrapper_map

    @property
    def is_http(self):
        """
        Get whether or not the request was over HTTP.
        :return: whether or not the request was over HTTP.
        """
        return self.requested_url_wrapper.is_http_scheme

    @property
    def is_https(self):
        """
        Get whether or not the request was over HTTPS.
        :return: whether or not the request was over HTTPS.
        """
        return self.requested_url_wrapper.is_https_scheme

    @property
    def request(self):
        """
        Get an HttpRequestWrapper instance that wraps the request contained within
        self.wrapped_data.
        :return: an HttpRequestWrapper instance that wraps the request contained within
        self.wrapped_data.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def request_duration(self):
        """
        Get a datetime.timedelta object that reflects how long it took to retrieve the response.
        :return: a datetime.timedelta object that reflects how long it took to retrieve the response.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def request_verb(self):
        """
        Get the HTTP verb that was used to access the remote service.
        :return: The HTTP verb that was used to access the remote service.
        """
        return self.request.method_string

    @property
    def requested_full_url_path(self):
        """
        Get the full URL path (including query string and URL fragment) for the URL that was requested.
        :return: the full URL path (including query string and URL fragment) for the URL that was requested.
        """
        return self.requested_url_wrapper.full_path_string

    @property
    def requested_host(self):
        """
        Get the host that was requested by self.request.
        :return: the host that was requested by self.request.
        """
        return self.request.requested_host

    @property
    def requested_url(self):
        """
        Get the URL that was requested to generate the wrapped request and response.
        :return: the URL that was requested to generate the wrapped request and response.
        """
        return self.request.requested_url

    @property
    def requested_url_path(self):
        """
        Get a string representing the URL path that was requested.
        :return: a string representing the URL path that was requested.
        """
        return self.requested_url_wrapper.path

    @property
    def requested_url_wrapper(self):
        """
        Get a UrlWrapper that wraps self.requested_url.
        :return: a UrlWrapper that wraps self.requested_url.
        """
        return self.request.requested_url_wrapper

    @property
    def response(self):
        """
        Get an HttpResponseWrapper instance that wraps the response contained within
        self.wrapped_data.
        :return: an HttpResponseWrapper instance that wraps the response contained
        within self.wrapped_data.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def response_contains_html(self):
        """
        Get whether or not self.response contains HTML content.
        :return: whether or not self.response contains HTML content.
        """
        return self.response.content_is_html

    @property
    def response_content(self):
        """
        Get the content of the response.
        :return: the content of the response.
        """
        return self.response.content

    @property
    def response_content_hash(self):
        """
        Get an MD5 hash of the response's content.
        :return: an MD5 hash of the response's content.
        """
        return self.response.content_hash

    @property
    def response_content_length(self):
        """
        Get the length of the content contained by self.response.
        :return: the length of the content contained by self.response.
        """
        return self.response.content_length

    @property
    def response_content_wrapper(self):
        """
        Get the content wrapper from self.response.
        :return: the content wrapper from self.response.
        """
        return self.response.content_wrapper

    @property
    def response_has_content(self):
        """
        Get whether or not self.response contains a resource.
        :return: whether or not self.response contains a resource.
        """
        return self.response.has_content

    @property
    def response_mime_string(self):
        """
        Get the MIME type string returned by self.response.
        :return: the MIME type string returned by self.response.
        """
        return self.response.content_mime_string

    @property
    def response_mime_type(self):
        """
        Get the MIME type of the contents of the HTTP response.
        :return: the MIME type of the contents of the HTTP response.
        """
        return self.response.content_mime_type

    @property
    def response_status_code(self):
        """
        Get the HTTP status code returned by self.response.
        :return: the HTTP status code returned by self.response.
        """
        return self.response.status_code

    @property
    def wrapped_type(self):
        return "HTTP Transaction"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s %s (%s) %s>" % (
            self.__class__.__name__,
            self.request_verb,
            self.requested_url,
            self.response_status_code,
            self.response_mime_type,
        )


class HttpRequestWrapperBase(BaseWrapper):
    """
    This class serves as a wrapper around a single HTTP request. It should be sub-classed
    for every type of HTTP request that Web Sight will handle.
    """

    # Class Members

    _method_type = None
    _requested_url_wrapper = None
    _wrapped_headers = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def has_host_header(self):
        """
        Get whether or not this request has a Host header.
        :return: whether or not this request has a Host header.
        """
        return self.host_header is not None

    @property
    def headers(self):
        """
        Get a list of tuples containing (1) the header key and (2) the header value for
        every header supplied alongside the wrapped request.
        :return: a list of tuples containing (1) the header key and (2) the header value
        for every header supplied alongside the wrapped request.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def host_header(self):
        """
        Get an HttpRequestHeaderWrapper that wraps the Host header found in
        self.headers if such a header exists.
        :return: an HttpRequestHeaderWrapper that wraps the Host header found
        in self.headers if such a header exists.
        """
        results = filter(lambda x: x.is_host_header, self.wrapped_headers)
        return results[0] if len(results) > 0 else None

    @property
    def is_get_request(self):
        """
        Get whether or not this request was an HTTP GET request.
        :return: whether or not this request was an HTTP GET request.
        """
        return self.method_string.lower() == "get"

    @property
    def is_post_request(self):
        """
        Get whether or not this request was an HTTP POST request.
        :return: whether or not this request was an HTTP POST request.
        """
        return self.method_string.lower() == "post"

    @property
    def method_string(self):
        """
        Get a string representing the HTTP method type used in the request.
        :return: a string representing the HTTP method type used in the request.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def requested_host(self):
        """
        Get the host that was requested by the wrapped request.
        :return: the host that was requested by the wrapped request.
        """
        if self.has_host_header:
            return self.host_header.value
        else:
            return self.requested_url_wrapper.destination

    @property
    def requested_url(self):
        """
        Get the URL that was requested to generate the wrapped request and response.
        :return: the URL that was requested to generate the wrapped request and response.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def requested_url_wrapper(self):
        """
        Get a UrlWrapper object that wraps self.requested_url.
        :return: a UrlWrapper object that wraps self.requested_url.
        """
        from ...url import UrlWrapper
        if self._requested_url_wrapper is None:
            self._requested_url_wrapper = UrlWrapper(self.requested_url)
        return self._requested_url_wrapper

    @property
    def wrapped_headers(self):
        """
        Get a list of HttpRequestHeaderWrapper objects wrapping all of the headers
        found in self.headers.
        :return: a list of HttpRequestHeaderWrapper objects wrapping all of the headers
        found in self.headers.
        """
        if self._wrapped_headers is None:
            self._wrapped_headers = [HttpRequestHeaderWrapper(key=x[0], value=x[1]) for x in self.headers]
        return self._wrapped_headers

    @property
    def wrapped_type(self):
        return "HTTP Request"

    # Representation and Comparison


class HttpResponseWrapperBase(BaseWrapper):
    """
    This class serves as a wrapper around a single HTTP response. It should be sub-classed
    for every type of HTTP response that Web Sight will handle.
    """

    # Class Members

    _content_hash = None
    _content_wrapper = None
    _content_type_mime_wrapper = None
    _decoded_content = None
    _wrapped_headers = None
    _wrapper_map = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def content(self):
        """
        Get the content of the response.
        :return: the content of the response.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def content_hash(self):
        """
        Get an MD5 hash representing the contents of self.content_wrapper.
        :return: an MD5 hash representing the contents of self.content_wrapper.
        """
        if self._content_hash is None:
            self._content_hash = self.content_wrapper.get_hash()
        return self._content_hash

    @property
    def content_length(self):
        """
        Get the length of content found in this response, if a Content-Length header is present.
        :return: the length of content found in this response, if a Content-Length header is present.
        """
        if self.has_content_length_header:
            return int(self.content_length_header.value)
        else:
            logger.info(
                "No Content-Length header found, resorting to length of content instead."
            )
            return len(self.content)

    @property
    def content_length_header(self):
        """
        Get an HttpResponseHeaderWrapper wrapping the Content-Length header
        found in self.headers if such a header exists.
        :return: an HttpResponseHeaderWrapper wrapping the Content-Length header
        found in self.headers if such a header exists.
        """
        results = filter(lambda x: x.is_content_length_header, self.wrapped_headers)
        return results[0] if len(results) > 0 else None

    @property
    def content_is_html(self):
        """
        Get whether or not the contents of this response contain HTML.
        :return: whether or not the contents of this response contain HTML.
        """
        if self.has_content_type_header:
            return self.content_mime_type == "html"
        else:
            return False

    @property
    def content_mime_string(self):
        """
        Get the MIME string returned by the wrapped response.
        :return: the MIME string returned by the wrapped response.
        """
        if self.has_content_type_header:
            return self.content_type_header.value
        else:
            return None

    @property
    def content_mime_type(self):
        """
        Get a constant representing the MIME type of the data contained within the response.
        :return: a constant representing the MIME type of the data contained within the response.
        """
        if self.has_content_type_header:
            try:
                return self.content_type_mime_wrapper.type
            except InvalidMimeStringError as e:
                logger.error(
                    "Invalid MIME string error thrown when processing %s: %s"
                    % (self.content_mime_string, e.message)
                )
                return "unknown"
        else:
            return "unknown"

    @property
    def content_type_header(self):
        """
        Get an HttpResponseHeaderWrapper wrapping the Content-Type header found
        in self.headers if such a header exists.
        :return: an HttpResponseHeaderWrapper wrapping the Content-Type header
        found in self.headers if such a header exists.
        """
        results = filter(lambda x: x.is_content_type_header, self.wrapped_headers)
        return results[0] if len(results) > 0 else None

    @property
    def content_type_mime_wrapper(self):
        """
        Get a MimeWrapper object wrapping the MIME type found in self.content_type_header
        if a Content-Type header is present and its MIME type is valid.
        :return: a MimeWrapper object wrapping the MIME type found in self.content_type_header
        if a Content-Type header is present and its MIME type is valid.
        """
        if self._content_type_mime_wrapper is None and self.has_content_type_header:
            from ...mime import MimeWrapper
            self._content_type_mime_wrapper = MimeWrapper(self.content_mime_string)
        return self._content_type_mime_wrapper

    @property
    def content_wrapper(self):
        """
        Get an instance of a wrapper class that wraps self.decoded_content.
        :return: an instance of a wrapper class that wraps self.decoded_content.
        """
        if self._content_wrapper is None:
            if self.content_wrapper_class_exists:
                wrapper_class = self.wrapper_map[self.content_mime_type]
                self._content_wrapper = wrapper_class(self.decoded_content)
            else:
                self._content_wrapper = UnknownWrapper(self.decoded_content)
        return self._content_wrapper

    @property
    def content_wrapper_class_exists(self):
        """
        Get whether or not a wrapper class exists for the MIME type of self.content.
        :return: whether or not a wrapper class exists for the MIME type of self.content.
        """
        return self.content_mime_type in self.wrapper_map

    @property
    def decoded_content(self):
        """
        Get the content of the response decoded by self.encoding.
        :return: the content of the response decoded by self.encoding.
        """
        if self._decoded_content is None:
            if self.encoding is not None:
                self._decoded_content = self.content.decode(self.encoding).encode(config.gen_default_encoding)
            else:
                logger.info(
                    "No encoding found for content. Going to resort to plain content."
                )
                self._decoded_content = self.content
        return self._decoded_content

    @property
    def encoding(self):
        """
        Get a string representing the encoding used by the data found in the wrapped response.
        :return: a string representing the encoding used by the data found in the wrapped response.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def has_content(self):
        """
        Get whether or not this response contains any content to process.
        :return: whether or not this response contains any content to process.
        """
        return self.content_length > 0

    @property
    def has_content_length_header(self):
        """
        Get whether or not self.headers contains a Content-Length header.
        :return: whether or not self.headers contains a Content-Length header.
        """
        return self.content_length_header is not None

    @property
    def has_content_type_header(self):
        """
        Get whether or not self.headers contains a Content-Type header.
        :return: whether or not self.headers contains a Content-Type header.
        """
        return self.content_type_header is not None

    @property
    def headers(self):
        """
        Get a list of tuples containing (1) the header key and (2) the header value for
        every header supplied alongside the wrapped response.
        :return: a list of tuples containing (1) the header key and (2) the header value
        for every header supplied alongside the wrapped response.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def status_code(self):
        """
        Get the HTTP response status code as an integer from the wrapped response.
        :return: the HTTP response status code as an integer from the wrapped response.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def wrapped_headers(self):
        """
        Get a list of HttpResponseHeaderWrapper objects wrapping all of the headers found
        in self.headers.
        :return: a list of HttpResponseHeaderWrapper objects wrapping all of the headers
        found in self.headers.
        """
        if self._wrapped_headers is None:
            self._wrapped_headers = [HttpResponseHeaderWrapper(key=x[0], value=x[1]) for x in self.headers]
        return self._wrapped_headers

    @property
    def wrapper_map(self):
        """
        Get a dictionary mapping MIME types to wrapper classes that can parse them.
        :return: a dictionary mapping MIME types to wrapper classes that can parse them.
        """
        if self._wrapper_map is None:
            self._wrapper_map = get_data_type_wrapper_map()
        return self._wrapper_map

    @property
    def wrapped_type(self):
        return "HTTP Response"

    # Representation and Comparison


class HttpHeaderWrapperBase(BaseWrapper):
    """
    This class is a base class for wrapper classes that wrap HTTP headers.
    """

    # Class Members

    _key = None
    _type = None
    _value = None

    # Instantiation

    def __init__(self, key=None, value=None):
        self._key = key
        self._value = value
        super(HttpHeaderWrapperBase, self).__init__("%s: %s" % (key, value))

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _get_type(self):
        """
        Get the HTTP response or request header type constant associated with self.key.
        :return: The HTTP response or request header type constant associated with self.key.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    # Properties

    @property
    def header_string(self):
        """
        Get a string representing the header as a whole.
        :return: a string representing the header as a whole.
        """
        return "%s: %s" % (self.key, self.value)

    @property
    def is_experimental(self):
        """
        Get whether or not this header is an experimental header.
        :return: whether or not this header is an experimental header.
        """
        return self.key.lower().startswith("x-")

    @property
    def key(self):
        """
        Get the key associated with the HTTP header.
        :return: the key associated with the HTTP header.
        """
        return self._key

    @property
    def type(self):
        """
        Get the HTTP response or request header type associated with self.key.
        :return: the HTTP response or request header type associated with self.key.
        """
        if self._type is None:
            self._type = self._get_type()
        return self._type

    @property
    def value(self):
        """
        Get the value associated with the HTTP header.
        :return: the value associated with the HTTP header.
        """
        return self._value

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.header_string)


class HttpRequestHeaderWrapper(HttpHeaderWrapperBase):
    """
    A wrapper class for wrapping HTTP request headers.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _get_type(self):
        return self.key.strip().lower()

    # Private Methods

    # Properties

    @property
    def is_cookie_header(self):
        """
        Get whether or not this is a Cookie header.
        :return: whether or not this is a Cookie header.
        """
        return self.type == "cookie"

    @property
    def is_host_header(self):
        """
        Get whether or not this is a Host header.
        :return: whether or not this is a Host header.
        """
        return self.type == "host"

    @property
    def is_user_agent_header(self):
        """
        Get whether or not this is a User-Agent header.
        :return: whether or not this is a User-Agent header.
        """
        return self.type == "user-agent"

    @property
    def wrapped_type(self):
        return "HTTP Request Header"

    # Representation and Comparison


class HttpResponseHeaderWrapper(HttpHeaderWrapperBase):
    """
    A wrapper class for wrapping HTTP response headers.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _get_type(self):
        return self.key.strip().lower()

    # Private Methods

    # Properties

    @property
    def is_content_length_header(self):
        """
        Get whether or not this header is a Content-Length header.
        :return: whether or not this header is a Content-Length header.
        """
        return self.type == "content-length"

    @property
    def is_content_type_header(self):
        """
        Get whether or not this header is a Content-Type header.
        :return: whether or not this header is a Content-Type header.
        """
        return self.type == "content-type"

    @property
    def is_location_header(self):
        """
        Get whether or not this header is a Location header.
        :return: whether or not this header is a Location header.
        """
        return self.type == "location"

    @property
    def is_set_cookie_header(self):
        """
        Get whether or not this header is a Set-Cookie header.
        :return: whether or not this header is a Set-Cookie header.
        """
        return self.type == "set-cookie"

    @property
    def wrapped_type(self):
        return "HTTP Response Header"

    # Representation and Comparison
