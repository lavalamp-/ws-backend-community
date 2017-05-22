# -*- coding: utf-8 -*-
from __future__ import absolute_import

from billiard import Process
import scrapy.settings
import logging
import sys
from scrapy.crawler import CrawlerProcess
import os

from lib import ConfigManager, FilesystemHelper
from lib.parsing.wrappers import ScrapyResultWrapper
from .spider import WsSpider
from .context import get_context_factory_for_hostname

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


class CrawlRunner(object):
    """
    This class is responsible for invoking Scrapy crawling sessions.
    """

    # Class Members

    # Instantiation

    def __init__(
            self,
            bot_name=config.crawling_bot_name,
            depth_limit=config.crawling_depth_limit,
            allow_all_errors=config.crawling_allow_all_error_codes,
            concurrent_requests=config.crawling_concurrent_requests,
            concurrent_items=config.crawling_concurrent_items,
            depth_priority=config.crawling_depth_priority,
            max_time=config.crawling_max_crawl_time,
            max_size=config.crawling_max_download_size,
            user_agent=config.crawling_user_agent,
            enable_telnet=config.crawling_enable_telnet_console,
    ):
        self.bot_name = bot_name
        self.depth_limit = depth_limit
        self.allow_all_errors = allow_all_errors
        self.concurrent_requests = concurrent_requests
        self.concurrent_items = concurrent_items
        self.depth_priority = depth_priority
        self.max_time = max_time
        self.max_size = max_size
        self.user_agent = user_agent
        self.enable_telnet = enable_telnet
        self._crawling_config = None

    # Static Methods

    # Class Methods

    # Public Methods

    def crawl_endpoint_to_file(
            self,
            ip_address=None,
            port=None,
            hostname=None,
            use_ssl=False,
            use_sni=False,
            start_urls=[],
            in_separate_process=True,
    ):
        """
        Start crawling the given endpoint using the given list of URLs and write the results to
        a local file.
        :param ip_address: The IP address to crawl.
        :param port: The port where the application resides.
        :param hostname: The hostname to submit alongside all requests to the remote endpoint.
        :param use_ssl: Whether or not to use SSL to connect to the remote web service.
        :param use_sni: Whether or not to use SNI to connect to the remote web service.
        :param start_urls: A list of URLs to start crawling from.
        :param in_separate_process: Whether or not to spawn off a separate process for the crawl. This
        enables us to call this method multiple times in the same process, as a Twisted reactor can only
        be started and stopped once per process.
        :return: A tuple containing (1) the string containing the local file path where crawling
        results are stored and (2) a ScrapyResultWrapper configured to process the contents of the file.
        """
        temp_file_path = FilesystemHelper.get_temporary_file_path()
        local_file_path = "%s-%s-%s:%s" % (temp_file_path, self.bot_name, ip_address, port)
        spider_kwargs = {
            "input_ip_address": ip_address,
            "input_start_urls": start_urls,
            "input_file_path": local_file_path,
            "input_hostname": hostname,
            "input_use_ssl": use_ssl,
            "input_use_sni": use_sni,
            "input_port": port,
        }
        pipeline_settings = self.__get_local_storage_item_pipeline()
        requested_hostname = hostname if hostname is not None else ip_address
        settings = self.get_scrapy_settings(item_pipeline=pipeline_settings, hostname=requested_hostname)
        crawling_config = {
            "spider_kwargs": spider_kwargs,
            "settings": settings,
        }
        if in_separate_process:
            process = Process(target=self.__crawl, kwargs=crawling_config)
            process.start()
            process.join()
            process.terminate()
        else:
            self.__crawl(**crawling_config)
        return local_file_path, ScrapyResultWrapper.from_file(local_file_path)

    def get_scrapy_settings(self, item_pipeline=None, hostname=None):
        """
        Get a scrapy settings dictionary to use for crawling web applications.
        :param item_pipeline: The item pipeline configuration to configure in the settings.
        :param hostname: The hostname to request by default in all Scrapy requests.
        :return: A scrapy settings dictionary to use for crawling web applications.
        """
        item_pipeline = item_pipeline if item_pipeline is not None else self.__get_default_item_pipeline()
        return scrapy.settings.Settings(values={
            "CONCURRENT_ITEMS": self.concurrent_items,
            "CONCURRENT_REQUESTS": self.concurrent_requests,
            "DEFAULT_REQUEST_HEADERS": {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en",
                "Host": hostname,
            },
            "DEPTH_LIMIT": self.depth_limit,
            "DEPTH_PRIORITY": self.depth_priority,
            "DOWNLOADER_CLIENTCONTEXTFACTORY": "lib.inspection.web.crawling.WebSightClientContextFactory",
            "EXTENSIONS": {
                "scrapy.extensions.telnet.TelnetConsole": None,
            },
            "DOWNLOADER_MIDDLEWARES": {
                "scrapy.downloadermiddlewares.redirect.RedirectMiddleware": None,
                "scrapy.downloadermiddlewares.redirect.MetaRefreshMiddleware": None,
            },
            "SPIDER_MIDDLEWARES": {
                "scrapy.spidermiddlewares.offsite.OffsiteMiddleware": None,
            },
            "DOWNLOAD_MAXSIZE": self.max_size,
            "HTTPERROR_ALLOW_ALL": self.allow_all_errors,
            "ITEM_PIPELINES": item_pipeline,
            "LOG_LEVEL": config.log_crawling_level,
            "TELNETCONSOLE_ENABLED": self.enable_telnet,
            "USER_AGENT": self.user_agent,
        })

    def get_spider_class_for_domain(
            self,
            input_ip_address=None,
            input_port=None,
            input_start_urls=[],
            input_file_path=None,
            input_hostname=None,
            input_use_ssl=None,
            input_use_sni=None,
    ):
        """
        Create and return an anonymous spider class that is configured to crawl the given domain
        and start from the given list of starting URLs.
        :param input_ip_address: The IP address of the remote web service to crawl.
        :param input_port: The port where the remote web service is running.
        :param input_start_urls: The URLs to start on.
        :param input_file_path: The local file path where results should be stored if using the local
        storage pipeline.
        :param input_hostname: The hostname to submit alongside all requests.
        :param input_use_ssl: Whether or not to use SSL to crawl the endpoint.
        :param input_use_sni: Whether or not to use SNI to crawl the endpoint.
        :return: A spider class configured to crawl the given domain and URLs.
        """

        if len(input_start_urls) == 0:
            base_url = "%s://%s:%s/" % ("https" if input_use_ssl else "http", input_ip_address, input_port)
            input_start_urls.append(base_url)

        class AnonSpider(WsSpider):
            allowed_domains = [input_ip_address]
            file_path = input_file_path
            hostname = input_hostname
            ip_address = input_ip_address
            name = "%s-%s" % (self.bot_name, input_hostname if input_hostname is not None else ip_address)
            max_run_time = self.max_time
            port = input_port
            start_urls = input_start_urls
            use_sni = input_use_sni
            use_ssl = input_use_ssl

        return AnonSpider

    # Protected Methods

    # Private Methods

    def __add_custom_context_factory_to_modules(self, hostname=None, classpath=None):
        """
        Create an anonymous client context factory for requesting the given hostname and add it
        to the imported modules.
        :param hostname: The hostname to request.
        :param classpath: The classpath to add the class to.
        :return: None
        """
        custom_factory = get_context_factory_for_hostname(hostname)
        sys.modules[classpath] = custom_factory

    def __crawl(self, spider_kwargs=None, settings=None):
        """
        Perform a crawl based on the contents of self._crawling_config.
        :param spider_kwargs: Keyword arguments to use to create a spider class.
        :param settings: Scrapy settings to use to crawl the remote endpoint.
        :return: None
        """
        print("SPIDER KWARGS ARE %s." % (spider_kwargs,))
        config.globals["%s-hostname" % (os.getpid(),)] = spider_kwargs["input_hostname"]
        spider = self.get_spider_class_for_domain(**spider_kwargs)
        process = CrawlerProcess(settings)
        process.crawl(spider)
        process.start()

    def __get_default_item_pipeline(self):
        """
        Get the default item pipeline configuration to use for scraping.
        :return: The default item pipeline configuration to use for scraping.
        """
        return self.__get_local_storage_item_pipeline()

    def __get_local_storage_item_pipeline(self):
        """
        Get a pipeline configuration for writing results to a local file.
        :return: A pipeline configuration for writing results to a local file.
        """
        return {
            "lib.inspection.web.crawling.pipeline.WsLocalStoragePipeline": 100,
        }

    # Properties

    @property
    def crawling_config(self):
        """
        Get a dictionary containing the spider and Scrapy settings to use to crawl an endpoint.
        :return: A dictionary containing the spider and Scrapy settings to use to crawl an endpoint.
        """
        return self._crawling_config

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.bot_name)

