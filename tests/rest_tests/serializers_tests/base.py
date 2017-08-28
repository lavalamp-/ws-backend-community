# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import WsDjangoTestCase


class BaseWebSightSerializerTestCase(WsDjangoTestCase):
    """
    This is a base test case class for all test cases that test a serializer class.
    """

    def get_populated_serializer(self, access_is_valid=True, **kwargs):
        """
        Get an instance of the serializer populated using the default values and
        overridden by the contents of kwargs.
        :param access_is_valid: Whether or not to call is_valid() before returning the
        serializer.
        :param kwargs: Keyword arguments to overwrite in the return value from
        _get_serializer_kwargs.
        :return: An instance of the serializer.
        """
        serial_kwargs = self._get_serializer_kwargs()
        serial_kwargs.update(kwargs)
        to_return = self.serializer(data=serial_kwargs)
        if access_is_valid:
            to_return.is_valid()
        return to_return

    def _get_serializer_kwargs(self):
        """
        Get a dictionary of keyword arguments to pass in to the serializer.
        :return: A dictionary of keyword arguments to pass in to the serializer.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def serializer(self):
        """
        Get the serializer that this test case is intended to test.
        :return: the serializer that this test case is intended to test.
        """
        raise NotImplementedError("Subclasses must implement this!")
