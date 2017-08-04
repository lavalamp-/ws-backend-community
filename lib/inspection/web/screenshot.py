# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
from selenium import webdriver
import time
import errno
import os
import signal
from billiard import Process

from lib import ConfigManager, ImageProcessingHelper, ElasticsearchableMixin, FilesystemHelper
from .requestor import WebServiceInspector
from wselasticsearch.models import HttpScreenshotModel
from ..base import BaseInspector
from lib.parsing import UrlWrapper

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


class HttpScreenshotter(BaseInspector, ElasticsearchableMixin):
    """
    This class handles taking screenshots of web applications in a headless browser.
    """

    # Class Members

    _driver = None
    _output_file_path = None

    # Instantiation

    def __init__(self):
        super(HttpScreenshotter, self).__init__()
        self.__set_endpoint()

    # Static Methods

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import HttpScreenshotModel
        return HttpScreenshotModel

    # Public Methods

    def clean_up(self):
        super(HttpScreenshotter, self).clean_up()
        self.close_driver()

    def close_driver(self):
        """
        Close the Selenium driver if it's open and remove the reference.
        :return: None
        """
        if self._driver is not None:
            self._driver.quit()
            self._driver = None

    def screenshot_endpoint(
            self,
            ip_address=None,
            port=None,
            hostname=None,
            use_ssl=False,
            use_sni=False,
            path="/",
            in_separate_process=False,
    ):
        """
        Take a screenshot of the given endpoint, save it to a local temporary file, and return the local
        file path.
        :param ip_address: The IP address where the web service resides.
        :param port: The port where the web service resides.
        :param hostname: The hostname to request.
        :param use_ssl: Whether or not to use SSL to request the endpoint.
        :param use_sni: Whether or not the endpoint uses SNI.
        :param path: The path of the resource to screenshot.
        :param in_separate_process: Whether or not to take the screenshot in a separate process. This is to
        address the incredibly long time that the Selenium webdriver can take when it hangs.
        :return: A tuple containing (1) the local file path where the screenshot was saved and (2) whether or not
        the screenshot was taken successfully.
        """
        logger.debug(
            "Now attempting to take a screenshot of the web service at %s:%s (%s). Hostname is %s, SNI support is %s."
            % (ip_address, port, "using SSL" if use_ssl else "plain HTTP", hostname, use_sni)
        )
        self.__set_endpoint(
            ip_address=ip_address,
            port=port,
            hostname=hostname,
            use_ssl=use_ssl,
            use_sni=use_sni,
            path=path,
        )
        self._output_file_path = self.get_temporary_file_path()
        if in_separate_process:
            process = Process(target=self.__take_screenshot)
            try:
                process.start()
                process.join(config.selenium_screenshot_delay + config.inspection_screenshot_join_timeout)
            except IOError as e:
                if e.errno == errno.EINTR:
                    logger.warning("Interrupted system call error received.")
                else:
                    raise e
            finally:
                if process.is_alive():
                    print("PROCESS IS ALIVE - PID IS %s" % (process.pid,))
                    os.kill(process.pid, signal.SIGTERM)
        else:
            self.__take_screenshot()
        return self.output_file_path, FilesystemHelper.does_file_exist(self.output_file_path)

    # Protected Methods

    def _to_es_model(self):
        return HttpScreenshotModel(
            url=self.url,
        )

    # Private Methods

    def __prepare_driver(self):
        """
        Prepare the Selenium web driver to take the screenshot.
        :return: None
        """
        self.driver.set_window_position(0, 0)
        self.driver.set_window_size(config.selenium_window_width, config.selenium_window_height)

    def __save_endpoint_to_file(self):
        """
        Send an HTTP request to the remote endpoint to get the content of the requested resource and
        save that content to the local filesystem.
        :return: The file path where the resource resides on the local filesystem.
        """
        web_inspector = WebServiceInspector(
            ip_address=self.ip_address,
            port=self.port,
            hostname=self.hostname,
            use_ssl=self.use_ssl,
        )
        transaction = web_inspector.get(path=self.path)
        temp_file_path = self.get_temporary_file_path(file_ext="html")
        FilesystemHelper.write_to_file(
            file_path=temp_file_path,
            data=transaction.response_content,
            write_mode="wb+",
        )
        return temp_file_path

    def __set_endpoint(
            self,
            ip_address=None,
            port=None,
            hostname=None,
            use_ssl=False,
            use_sni=False,
            path=None,
    ):
        """
        Set the internal state of this screenshotter to maintain information about the endpoint to
        screenshot.
        :param ip_address: The IP address where the web service resides.
        :param port: The port where the web service resides.
        :param hostname: The hostname to use to connect to the endpoint.
        :param use_ssl: Whether or not to use SSL to connect to the endpoint.
        :param use_sni: Whether or not to use SNI to connect to the endpoint.
        :param path: The URL path to request.
        :return: None
        """
        self._ip_address = ip_address
        self._port = port
        self._hostname = hostname
        self._use_ssl = use_ssl
        self._use_sni = use_sni
        self._path = path

    def __take_screenshot(self):
        """
        Take a screenshot of the configured endpoint.
        :return: None
        """
        # from lib import DnsResolutionHelper
        # dns_helper = DnsResolutionHelper.instance()
        self.__prepare_driver()
        # dns_helper.add_resolution(domain_name=self.hostname, ip_address=self.ip_address)
        self.driver.get(self.url)
        logger.debug(
            "Sleeping for %s seconds before saving screenshot for endpoint %s."
            % (config.selenium_screenshot_delay, self.url)
        )
        time.sleep(config.selenium_screenshot_delay)
        self.driver.save_screenshot(self.output_file_path)
        # dns_helper.remove_resolution(self.hostname)
        cropped_image = ImageProcessingHelper.crop_selenium_screenshot(self.output_file_path)
        cropped_image.save(self.output_file_path, format=config.selenium_screenshot_format)
        logger.debug(
            "Successfully took screenshot of URL %s, and saved to %s."
            % (self.url, self.output_file_path)
        )

    # Properties

    @property
    def driver(self):
        """
        Get the driver to use to create the snapshot.
        :return: the driver to use to create the snapshot.
        """
        if self._driver is None:
            self._driver = webdriver.PhantomJS(service_args=[
                "--ignore-ssl-errors=true",
                "--local-to-remote-url-access=true",
            ])
        return self._driver

    @property
    def hostname(self):
        """
        Get the hostname of the last screenshotted web service.
        :return: the hostname of the last screenshotted web service.
        """
        return self._hostname

    @property
    def ip_address(self):
        """
        Get the IP address that was last screenshotted.
        :return: the IP address that was last screenshotted.
        """
        return self._ip_address

    @property
    def output_file_path(self):
        """
        Get the local file path to where the most recent screenshot was saved.
        :return: the local file path to where the most recent screenshot was saved.
        """
        return self._output_file_path

    @property
    def path(self):
        """
        Get the URL path that was last screenshotted.
        :return: the URL path that was last screenshotted.
        """
        return self._path

    @property
    def port(self):
        """
        Get the port where the last screenshotted service resides.
        :return: the port where the last screenshotted service resides.
        """
        return self._port

    @property
    def url(self):
        """
        Get a string representing the URL of the endpoint configured to be screenshotted.
        :return: a string representing the URL of the endpoint configured to be screenshotted.
        """
        return self.url_wrapper.to_string()

    @property
    def url_wrapper(self):
        """
        Get a UrlWrapper representing the endpoint configured to be screenshotted.
        :return: a UrlWrapper representing the endpoint configured to be screenshotted.
        """
        return UrlWrapper.from_endpoint(
            hostname=self.hostname,
            port=self.port,
            use_ssl=self.use_ssl,
            path=self.path,
        )

    @property
    def use_sni(self):
        """
        Get whether or not SNI was used for the last screenshot.
        :return: whether or not SNI was used for the last screenshot.
        """
        return self._use_sni

    @property
    def use_ssl(self):
        """
        Get whether or not SSL was used for the last screenshot.
        :return: whether or not SSL was used for the last screenshot.
        """
        return self._use_ssl

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)

