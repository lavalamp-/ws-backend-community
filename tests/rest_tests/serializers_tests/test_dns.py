# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebSightSerializerTestCase
import rest.serializers
from lib import WsFaker


class DnsRecordTypeSerializerTestCase(BaseWebSightSerializerTestCase):
    """
    This is a test case for the DnsRecordTypeSerializer class.
    """

    def test_unknown_record_type_fails(self):
        """
        Tests that a serializer with an unknown record type fails.
        :return: None
        """
        serializer = self.get_populated_serializer(record_type="ASD!@#")
        self.assertIn("record_type", serializer.errors)

    def _get_serializer_kwargs(self):
        return WsFaker.get_dns_record_type_kwargs()

    @property
    def serializer(self):
        return rest.serializers.DnsRecordTypeRelatedSerializer
