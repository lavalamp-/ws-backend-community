# -*- coding: utf-8 -*-
from __future__ import absolute_import

import scrapy
from scrapy.exceptions import CloseSpider
import logging

from lib import DatetimeHelper, ConfigManager
from .scraping import WebSightScraper

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


class WsSpider(scrapy.Spider):
    """
    This is the base spider used for crawling web applications in the Web Sight platform.
    """

    # Class Members

    allowed_domains = []
    file_path = None
    hostname = None
    ip_address = None
    max_run_time = None
    name = None
    port = None
    start_time = None
    start_urls = []
    use_sni = None
    use_ssl = None
    _scraper = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def close(self, reason):
        """
        This method is called when the spider is closed.
        :param reason: The signal that caused the spider to close.
        :return: None
        """
        pass

    def parse(self, response):
        """
        Parse the contents of the given response into Scrapy items.
        :param response: The response to parse.
        :return: Scrapy items as well as Scrapy requests.
        """
        for parsed in self.scraper.parse_response(response):
            yield parsed

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def scraper(self):
        """
        Get the Web Sight scraper to use to process responses.
        :return: the Web Sight scraper to use to process responses.
        """
        if self._scraper is None:
            self._scraper = WebSightScraper(self)
        return self._scraper

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s)>" % (
            self.__class__.__name__,
            self.name,
            ", ".join(self.allowed_domains),
        )

