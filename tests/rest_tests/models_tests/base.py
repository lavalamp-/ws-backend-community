# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import WsDjangoTestCase


class BaseWebSightModelTestCase(WsDjangoTestCase):
    """
    This is a base test case for all test cases that test a model class.
    """

    def create_instance(self, **kwargs):
        """
        Create an instance of the tested model class.
        :param kwargs: Keyword args.
        :return: The newly-created model object.
        """
        raise NotImplementedError("Subclasses must implememt this!")

    @property
    def model_class(self):
        """
        Get the model class that this test case is responsible for testing.
        :return: the model class that this test case is responsible for testing.
        """
        raise NotImplementedError("Subclasses must implement this!")
