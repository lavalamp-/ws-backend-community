# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseWebSightTestCase
from lib.deploy import DeployChecker


class DeployCheckerTestCase(BaseWebSightTestCase):
    """
    This is a test case for ensuring that the various dependencies required by Web Sight are
    present and working.
    """

    _checker = None

    def test_zmap_present(self):
        """
        Test to ensure that the zmap tool is available.
        :return: None
        """
        self.assertTrue(self.checker.zmap_present)

    def test_nmap_present(self):
        """
        Test to ensure that the nmap tool is available.
        :return: None
        """
        self.assertTrue(self.checker.nmap_present)

    def test_phantomjs_present(self):
        """
        Test to ensure that the PhantomJS tool is available.
        :return: None
        """
        self.assertTrue(self.checker.phantomjs_present)

    @property
    def checker(self):
        """
        Get an instance of the DeployChecker class to use to test for software dependencies.
        :return: An instance of the DeployChecker class to use to test for software dependencies.
        """
        if self._checker is None:
            self._checker = DeployChecker()
        return self._checker
