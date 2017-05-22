# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import DictableMixin


class BaseElasticsearchComponent(DictableMixin):
    """
    A base class for Elasticsearch component classes.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def key(self):
        return self.name

    @property
    def name(self):
        """
        Get the basic component name.
        :return: The basic component name.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def value(self):
        """
        Get the query value as a dictionary.
        :return: The query value as a dictionary.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Representation and Comparison
