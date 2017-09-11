# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebSightSerializerTestCase
import rest.serializers
from lib import WsFaker


class ScanConfigSerializerTestCase(BaseWebSightSerializerTestCase):
    """
    This is a test case for the ScanConfigSerializer class.
    """

    def test_invalid_zmap_bandwidth(self):
        """
        Tests that the serializer rejects data with an invalid Zmap scan
        bandwidth.
        :return: None
        """
        serializer = self.get_populated_serializer(network_scan_bandwidth="NAHBRUH")
        self.assertIn("network_scan_bandwidth", serializer.errors)

    def _get_serializer_kwargs(self):
        return WsFaker.get_scan_config_kwargs()

    @property
    def serializer(self):
        return rest.serializers.ScanConfigSerializer
