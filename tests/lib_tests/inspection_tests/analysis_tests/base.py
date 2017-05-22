# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ...base import BaseSqlalchemyTestCase


class BaseAnalysisInspectorTestCase(BaseSqlalchemyTestCase):
    """
    This is a base class for all test cases that test functionality found within analysis inspector
    classes.
    """

    # Class Members

    _inspector = None
    _es_populated = False

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def setUp(self):
        """
        Set up this test case by ensuring that a fresh inspector will be created in each case.
        :return: None
        """
        super(BaseAnalysisInspectorTestCase, self).setUp()
        self.__populate_elasticsearch()
        self._inspector = None

    # Protected Methods

    def _get_inspector_class(self):
        """
        Get the inspector class that this test case is meant to test.
        :return: The inspector class that this test case is meant to test.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _get_inspector_kwargs(self):
        """
        Get the keyword arguments to pass to the inspector instantiation.
        :return: A dictionary containing keyword arguments to pass to the inspector instantiation.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _populate_elasticsearch(self):
        """
        Populate Elasticsearch with all of the necessary data to power the analysis class being tested.
        :return: None
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    def __get_inspector(self):
        """
        Get an instance of the inspector that this test case is meant to test.
        :return: An instance of the inspector that this test case is meant to test.
        """
        return self._get_inspector_class()(**self._get_inspector_kwargs())

    def __populate_elasticsearch(self):
        """
        Populate Elasticsearch with all of the necessary data to power the analysis class being tested.
        :return: None
        """
        if not self.__class__._es_populated:
            self._populate_elasticsearch()
            self.__class__._es_populated = True

    # Properties

    @property
    def inspector(self):
        """
        Get the inspector to use to analyze gathered data.
        :return: the inspector to use to analyze gathered data.
        """
        if self._inspector is None:
            self._inspector = self.__get_inspector()
        return self._inspector

    # Representation and Comparison
