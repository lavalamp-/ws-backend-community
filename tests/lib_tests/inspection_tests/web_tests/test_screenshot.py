# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib.inspection import HttpScreenshotter
from lib import FilesystemHelper
from ....base import BaseWebSightTestCase


class HttpScreenshotterTestCase(BaseWebSightTestCase):
    """
    This is a test case for testing all of the functionality found within the HttpScreenshotter
    class.
    """

    _screenshotter = None
    _screenshot_path = None

    def setUp(self):
        """
        Handle the setting up of this class to have a reference to the screenshotter to use for
        testing purposes.
        :return: None
        """
        super(HttpScreenshotterTestCase, self).setUp()
        self._screenshotter = HttpScreenshotter()
        self._screenshot_path = None

    def tearDown(self):
        """
        Handle the tearing down of this class by deleting any pictures that were taken by the
        test suite.
        :return: None
        """
        if self._screenshot_path is not None:
            FilesystemHelper.delete_file(self._screenshot_path)
        super(HttpScreenshotterTestCase, self).tearDown()

    def __take_screenshot(
            self,
            ip_address="74.125.204.105",
            port=443,
            hostname="www.google.com",
            use_ssl=True,
            in_separate_process=False,
    ):
        """
        Take a screenshot using self.screenshotter.screenshot_endpoint using the given values.
        :param ip_address: The IP address to get a screenshot of.
        :param port: The port to connect to.
        :param hostname: The hostname to use in the connection.
        :param use_ssl: Whether or not to use SSL to connect to the endpoint.
        :param in_separate_process: Whether or not to take the screenshot in a separate
        process.
        :return: The return value of the screenshot_endpoint invocation.
        """
        return self.screenshotter.screenshot_endpoint(
            ip_address=ip_address,
            port=port,
            hostname=hostname,
            use_ssl=use_ssl,
            in_separate_process=in_separate_process
        )

    def test_screenshot_endpoint_http_succeeds(self):
        """
        Tests to ensure that taking a screenshot of an HTTP endpoint succeeds.
        :return: None
        """
        self._screenshot_path, success = self.__take_screenshot(port=80, use_ssl=False)
        self.assertTrue(success)

    def test_screenshot_endpoint_https_succeeds(self):
        """
        Tests to ensure that taking a screenshot of an HTTPS endpoint succeeds.
        :return: None
        """
        self._screenshot_path, success = self.__take_screenshot()
        self.assertTrue(success)

    def test_screenshot_endpoint_separate_succeeds(self):
        """
        Tests to ensure that the screenshot_endpoint method successfully takes a screenshot when
        run in a separate process.
        :return: None
        """
        self._screenshot_path, success = self.__take_screenshot(in_separate_process=True)
        self.assertTrue(success)

    def test_screenshot_endpoint_separate_creates_file(self):
        """
        Tests to ensure that the screenshot_endpoint method successfully creates a file containing
        the screenshot when run in a separate process.
        :return: None
        """
        self._screenshot_path, success = self.__take_screenshot(in_separate_process=True)
        self.assertTrue(FilesystemHelper.does_file_exist(self._screenshot_path))

    def test_screenshot_endpoint_same_succeeds(self):
        """
        Tests to ensure that the screenshot_endpoint method successfully takes a screenshot when
        run in the same process.
        :return: None
        """
        self._screenshot_path, success = self.__take_screenshot(in_separate_process=False)
        self.assertTrue(success)

    def test_screenshot_same_creates_file(self):
        """
        Tests to ensure that the screenshot_endpoint method successfully creates a file containing
        the screenshot when run in the same process.
        :return: None
        """
        self._screenshot_path, success = self.__take_screenshot(in_separate_process=False)
        self.assertTrue(FilesystemHelper.does_file_exist(self._screenshot_path))

    @property
    def screenshotter(self):
        """
        Get the HttpScreenshotter instance to use during testing.
        :return: The HttpScreenshotter instance to use during testing.
        """
        return self._screenshotter
