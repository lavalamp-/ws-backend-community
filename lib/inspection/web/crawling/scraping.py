# -*- coding: utf-8 -*-
from __future__ import absolute_import

import scrapy
import logging
from scrapy.exceptions import CloseSpider
from base64 import b64encode
from lxml import etree

from lib import HashHelper, ConfigManager, DatetimeHelper, CrawlableMixin
from lib.parsing.wrappers.exception import InvalidUrlError
from lib.parsing.wrappers.mime.exception import InvalidMimeStringError
from .item import HttpTransaction, HttpResource
from lib.parsing import UrlWrapper, get_data_type_wrapper_map, MimeWrapper, get_header_wrapper_map, ScrapyTransactionWrapper

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


class WebSightScraper(object):
    """
    This class is responsible for handling the scraping of all Scrapy items and requests from
    responses retrieved via Scrapy.
    """

    # Class Members

    # Instantiation

    def __init__(self, spider):
        self._spider = spider
        self._base_url_wrapper = None
        self._base_url = None
        self._data_type_wrapper_map = None
        self._header_wrapper_map = None
        self._tracked_references = []
        self._start_time = None
        self._errors = []

    # Static Methods

    # Class Methods

    # Public Methods

    def parse_response(self, response):
        """
        Parse the contents of the given Scrapy response and return a generator that iterates over
        Scrapy requests first followed by the Scrapy items.
        :param response: The response to process.
        :return: A generator that will iterate over Scrapy requests generated from the response first
        followed by Scrapy items.
        """
        wrapper = ScrapyTransactionWrapper(response)
        for scrapy_item in wrapper.iter_scrapy_items():
            yield scrapy_item
        for found_method, reference_wrapper in wrapper.url_tuples:
            request = self.__parse_reference_wrapper(
                reference_wrapper=reference_wrapper,
                requested_url_wrapper=wrapper.requested_url_wrapper,
            )
            if request is not None:
                yield request
        self.__check_for_close()

    # Protected Methods

    # Private Methods

    def __add_reference_for_tracking(self, reference_wrapper=None, crawled=None):
        """
        Add the contents of the given reference wrapper to the log of references being tracked for
        this spidering session.
        :param reference_wrapper: The HttpReferenceWrapper to track.
        :param crawled: Whether or not the reference in the wrapper was crawled.
        :return: None
        """
        if config.crawling_track_references:
            self._tracked_references.append((crawled, reference_wrapper.wrapped_data))

    def __check_for_close(self):
        """
        Check to see if this spider has been running for longer than the maximum amount
        of allowed time, and stop the spider if it has.
        :return: None
        """
        if self._start_time is None:
            self._start_time = DatetimeHelper.now()
        elapsed_time = (DatetimeHelper.now() - self.start_time).total_seconds()
        if elapsed_time > self.max_run_time:
            raise CloseSpider(
                "Spider run time exceeded maximum time of %s seconds. Closing."
                % (self.max_run_time,)
            )

    def __create_request(self, url=None):
        """
        Create and return a Scrapy request based on the contents of the arguments passed to this
        method.
        :param url: The URL to set in the request.
        :return: A Scrapy request.
        """
        return scrapy.Request(
            url,
            callback=self.parse_response,
            errback=self.__handle_error,
        )

    def __create_request_from_reference_path(self, reference_wrapper=None, requested_url_wrapper=None):
        """
        Create and return a Scrapy request based on the contents of the given HttpReferenceWrapper.
        :param reference_wrapper: The HttpReferenceWrapper to process.
        :param requested_url_wrapper: A UrlWrapper containing the URL that was requested.
        :return: A Scrapy request based on the contents of the given HttpReferenceWrapper.
        """
        new_wrapper = requested_url_wrapper.resolve_against(path=reference_wrapper.wrapped_data)
        return self.__create_request(url=new_wrapper.to_string())

    def __create_request_from_url_wrapper(self, url_wrapper=None, requested_url_wrapper=None):
        """
        Create and return a Scrapy request based on the contents of the given UrlWrapper.
        :param url_wrapper: The UrlWrapper to process.
        :param requested_url_wrapper: A UrlWrapper containing the URL that was requested.
        :return: A Scrapy request based on the contents of the given UrlWrapper.
        """
        new_wrapper = requested_url_wrapper.resolve_against(path=url_wrapper.full_path_string)
        return self.__create_request(url=new_wrapper.to_string())

    def __get_content_length_from_response(self, response):
        """
        Get the length of the content in the given response.
        :param response: The response to process.
        :return: The length of the content in the given response.
        """
        if "Content-Length" in response.headers:
            return int(response.headers["Content-Length"])
        else:
            return len(response.body)

    def __get_content_type_from_response(self, response):
        """
        Get a MIME content type depicting the type of data found in the given response.
        :param response: The response to get the content type for.
        :return: A MIME content type depicting the type of data found in the given response.
        """
        if "Content-Type" in response.headers:
            try:
                mime_wrapper = MimeWrapper(response.headers.get("Content-Type"))
                return mime_wrapper.type
            except InvalidMimeStringError:
                logger.error(
                    "Could not successfully process content type of %s."
                    % (response.headers.get("Content-Type"),)
                )
                return "unknown"
        else:
            return "unknown"

    def __get_http_resource_from_response(self, response):
        """
        Process the contents of the given Scrapy response and return an HttpResource item.
        :param response: The Scrapy response to process.
        :return: An HttpResource item representing the contents of response.
        """
        request_headers = self.__http_header_dict_to_tuples(response.request.headers)
        encoded_body = b64encode(response.body)
        return HttpResource(
            requested_url=response.url,
            request_headers=request_headers,
            request_method=response.request.method,
            query_arguments=None,
            body_arguments=None,
            response_status=response.status,
            content_type=response.headers.get("Content-Type", None),
            content_length=self.__get_content_length_from_response(response),
            content_hash=HashHelper.sha256_digest(response.body),
            content_secondary_hash=None,
            content=encoded_body,
        )

    def __get_http_transaction_from_response(self, response):
        """
        Process the contents of the given Scrapy response and return an HttpTransaction item.
        :param response: The Scrapy response to process.
        :return: An HttpTransaction item representing the contents of response.
        """
        request_headers = self.__http_header_dict_to_tuples(response.request.headers)
        response_headers = self.__http_header_dict_to_tuples(response.headers)
        return HttpTransaction(
            requested_url=response.url,
            request_headers=request_headers,
            request_method=response.request.method,
            query_arguments=None,
            body_arguments=None,
            response_status=response.status,
            response_headers=response_headers,
            response_content_type=response.headers.get("Content-Type", None),
            response_content_length=self.__get_content_length_from_response(response),
            response_content_hash=HashHelper.sha256_digest(response.body),
            response_content_secondary_hash=None,
        )

    def __handle_error(self, error):
        """
        Handle the given error that was thrown while crawling.
        :param error: The error that was thrown.
        :return: None
        """
        self._errors.append(error)

    def __http_header_dict_to_tuples(self, headers):
        """
        Process the contents of the headers dictionary and return a list of tuples representing all
        of the headers.
        :param headers: The header dictionary to process.
        :return: A list of tuples representing all of the headers in headers.
        """
        to_return = []
        for k, v in headers.iteritems():
            if isinstance(v, list):
                for value in v:
                    to_return.append((k, value))
            else:
                to_return.append((k, v))
        return to_return

    def __parse_body_for_requests(self, body=None, requested_url_wrapper=None, content_type=None):
        """
        Parse the contents of the given response body and yield any requests generated through URLs found within
        the data.
        :param body: The HTTP response body to process.
        :param requested_url_wrapper: A UrlWrapper wrapping the contents of the requested URL.
        :param content_type: A string representing the content type of the response body.
        :return: A generator iterating over all requests created through parsing the data.
        """
        if content_type in self.data_type_wrapper_map:
            wrapper_class = self.data_type_wrapper_map[content_type]
            if issubclass(wrapper_class, CrawlableMixin):
                for request in self.__parse_crawlable_wrapper_for_requests(
                        to_wrap=body,
                        wrapper_class=wrapper_class,
                        requested_url_wrapper=requested_url_wrapper,
                ):
                    yield request
            else:
                self.logger.warning(
                    "No crawlable wrapper class exists for content type of %s."
                    % (content_type,)
                )

    def __parse_crawlable_wrapper_for_requests(
            self,
            to_wrap=None,
            wrapper_class=None,
            requested_url_wrapper=None,
    ):
        """
        Parse the contents of the given data using the given wrapper class and yield any requests that result
        from parsing.
        :param to_wrap: The value to wrap.
        :param wrapper_class: The CrawlableMixin subclass to wrap to_wrap with.
        :param requested_url_wrapper: A UrlWrapper containing the URL that was requested.
        :return: A generator that will iterate over all of the requests generated from URLs in the data.
        """
        try:
            wrapper = wrapper_class(to_wrap)
            url_tuples = wrapper.url_tuples
            for found_method, reference_wrapper in url_tuples:
                request = self.__parse_reference_wrapper(
                    reference_wrapper=reference_wrapper,
                    requested_url_wrapper=requested_url_wrapper,
                )
                if request is not None:
                    yield request
        except etree.Error as e:
            self.logger.error(
                "Error thrown when attempting to parse URL tuples from wrapper of type %s. Error was %s."
                % (wrapper_class.__name__, e.message)
            )

    def __parse_headers_for_requests(self, headers=None, requested_url_wrapper=None):
        """
        Parse the contents of the given headers and yield any requests generated through URLs found within them.
        :param headers: A Scrapy headers object.
        :param requested_url_wrapper: A UrlWrapper wrapping the contents of the requested URL.
        :return: A generator iterating over all requests created through parsing the headers.
        """
        for key in headers.keys():
            if key not in self.header_wrapper_map:
                continue
            wrapper_class = self.header_wrapper_map[key]
            if issubclass(wrapper_class, CrawlableMixin):
                for value in headers.getlist(key):
                    for request in self.__parse_crawlable_wrapper_for_requests(
                        to_wrap=value,
                        wrapper_class=wrapper_class,
                        requested_url_wrapper=requested_url_wrapper,
                    ):
                        yield request
            else:
                self.logger.warning(
                    "No crawlable wrapper class exists for header type of %s."
                    % (key,)
                )

    def __parse_reference_wrapper(self, reference_wrapper=None, requested_url_wrapper=None):
        """
        Process the contents of the given HttpReferenceWrapper and return a request if a request is parsed
        from the wrapper contents.
        :param reference_wrapper: The HttpReferenceWrapper to process.
        :param requested_url_wrapper: A UrlWrapper wrapping the contents of the requested URL.
        :return: A Scrapy request if a request is generated from the reference wrapper, otherwise None.
        """
        if not reference_wrapper.is_http_reference:
            return
        if reference_wrapper.has_http_protocol:
            try:
                url_wrapper = reference_wrapper.to_url_wrapper()
                if not self.base_url_wrapper.has_same_origin(url_wrapper=url_wrapper, include_host=False):
                    return
                if url_wrapper.destination not in [self.ip_address, self.hostname]:
                    return
                self.__add_reference_for_tracking(reference_wrapper=reference_wrapper, crawled=True)
                return self.__create_request_from_url_wrapper(
                    url_wrapper=url_wrapper,
                    requested_url_wrapper=requested_url_wrapper,
                )
            except InvalidUrlError as e:
                logger.error("Error thrown when processing URL: %s" % (e.message,))
        elif reference_wrapper.is_path:
            self.__add_reference_for_tracking(reference_wrapper=reference_wrapper, crawled=True)
            return self.__create_request_from_reference_path(
                reference_wrapper=reference_wrapper,
                requested_url_wrapper=requested_url_wrapper,
            )
        else:
            self.__add_reference_for_tracking(reference_wrapper=reference_wrapper, crawled=False)

    def __parse_response_for_items(self, response):
        """
        Parse the contents of the given Scrapy response and return a generator that will iterate over
        all of the items generated from the response.
        :param response: The Scrapy response to process.
        :return: A generator that will iterate over all of the items generated from the response.
        """
        yield self.__get_http_transaction_from_response(response)
        # content_length = self.__get_content_length_from_response(response)
        # if content_length < config.crawling_max_index_size:
        #     yield self.__get_http_resource_from_response(response)

    def __parse_response_for_requests(self, response):
        """
        Parse the contents of the given Scrapy response and return a generator that will iterate over
        all of the requests generated from URLs in the response.
        :param response: The response to process.
        :return: A generator that will iterate over all of the requests generated from URLs in the response.
        """
        requested_url_wrapper = UrlWrapper(response.url)
        for request in self.__parse_headers_for_requests(
                headers=response.headers,
                requested_url_wrapper=requested_url_wrapper,
        ):
            yield request
        content_length = self.__get_content_length_from_response(response)
        if content_length <= 0:
            return
        content_type = self.__get_content_type_from_response(response)
        for request in self.__parse_body_for_requests(
                body=response.body,
                requested_url_wrapper=requested_url_wrapper,
                content_type=content_type,
        ):
            yield request

    # Properties

    @property
    def base_url(self):
        """
        Get a string representing the base URL for the remote endpoint.
        :return: a string representing the base URL for the remote endpoint.
        """
        if self._base_url is None:
            self._base_url = self.base_url_wrapper.to_string()
        return self._base_url

    @property
    def base_url_wrapper(self):
        """
        Get a UrlWrapper representing the base URL for the remote web service.
        :return: a UrlWrapper representing the base URL for the remote web service.
        """
        if self._base_url_wrapper is None:
            self._base_url_wrapper = UrlWrapper.from_endpoint(
                hostname=self.ip_address,
                port=self.port,
                use_ssl=self.use_ssl,
                path="/",
            )
        return self._base_url_wrapper

    @property
    def data_type_wrapper_map(self):
        """
        Get a dictionary mapping MIME content types to classes that are built to parse the given type.
        :return: a dictionary mapping MIME content types to classes that are built to parse the given type.
        """
        if self._data_type_wrapper_map is None:
            self._data_type_wrapper_map = get_data_type_wrapper_map()
        return self._data_type_wrapper_map

    @property
    def errors(self):
        """
        Get a list of the errors that were thrown while crawling.
        :return: a list of the errors that were thrown while crawling.
        """
        return self._errors

    @property
    def header_wrapper_map(self):
        """
        Get a dictionary mapping HTTP header keys to wrapper classes meant to process them.
        :return: a dictionary mapping HTTP header keys to wrapper classes meant to process them.
        """
        if self._header_wrapper_map is None:
            self._header_wrapper_map = get_header_wrapper_map()
        return self._header_wrapper_map

    @property
    def hostname(self):
        """
        Get the hostname currently being spidered.
        :return: the hostname currently being spidered.
        """
        return self.spider.hostname

    @property
    def ip_address(self):
        """
        Get the IP address where the web service being crawled resides.
        :return: the IP address where the web service being crawled resides.
        """
        return self.spider.ip_address

    @property
    def logger(self):
        """
        Get the logger to use.
        :return: the logger to use.
        """
        return self.spider.logger

    @property
    def max_run_time(self):
        """
        Get the maximum amount of time in seconds that crawling should run before stopping.
        :return: the maximum amount of time in seconds that crawling should run before stopping.
        """
        return self.spider.max_run_time

    @property
    def port(self):
        """
        Get the port where the web service being crawled resides.
        :return: the port where the web service being crawled resides.
        """
        return self.spider.port

    @property
    def spider(self):
        """
        Get the spider that created this scraper object.
        :return: The spider that created this scraper object.
        """
        return self._spider

    @property
    def start_time(self):
        """
        Get the time at which the spider that created this scraper started running.
        :return: the time at which the spider that created this scraper started running.
        """
        return self._start_time

    @property
    def use_sni(self):
        """
        Get whether or not SNI is being used to communicate with the web service.
        :return: whether or not SNI is being used to communicate with the web service.
        """
        return self.spider.use_sni

    @property
    def tracked_references(self):
        """
        Get a list containing the references found during this crawling session and
        whether or not they were crawled.
        :return: a list containing the references found during this crawling session
        and whether or not they were crawled.
        """
        return self._tracked_references

    @property
    def use_ssl(self):
        """
        Get whether or not SSL is being used to communicate with the web service.
        :return: whether or not SSL is being used to communicate with the web service.
        """
        return self.spider.use_ssl

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)

