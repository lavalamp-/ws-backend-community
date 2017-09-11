# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebSightSerializerTestCase
import rest.serializers
from lib import WsFaker


class ScanPortSerializerTestCase(BaseWebSightSerializerTestCase):
    """
    This is a test case for the ScanPortSerializer class.
    """

    def test_non_int_port_fails(self):
        """
        Tests that a serializer with a non-integer value for the port number
        fails.
        :return: None
        """
        serializer = self.get_populated_serializer(port_number="ASD")
        self.assertIn("port_number", serializer.errors)

    def test_negative_int_port_fails(self):
        """
        Tests that a serializer with a negative port number fails.
        :return: None
        """
        serializer = self.get_populated_serializer(port_number=-1)
        self.assertIn("port_number", serializer.errors)

    def test_too_large_port_number_fails(self):
        """
        Tests that a serializer with too large of a port number fails.
        :return: None
        """
        serializer = self.get_populated_serializer(port_number=65536)
        self.assertIn("port_number", serializer.errors)

    def test_unknown_protocol_fails(self):
        """
        Tests that a serializer with an unknown protocol fails.
        :return: None
        """
        serializer = self.get_populated_serializer(protocol="LOLNAHHH")
        self.assertIn("protocol", serializer.errors)

    def _get_serializer_kwargs(self):
        return WsFaker.get_scan_port_kwargs()

    @property
    def serializer(self):
        return rest.serializers.ScanPortSerializer
