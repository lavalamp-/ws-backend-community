# -*- coding: utf-8 -*-
from __future__ import absolute_import


class BaseElasticsearchType(object):
    """
    A base class for Elasticsearch types as used by Web Sight Elasticsearch models.
    """

    # Class Members

    # Instantiation

    def __init__(self, index=None, diffable=False, diff_key=None, help_text=None):
        from lib import ValidationHelper
        if index is not None:
            ValidationHelper.validate_bool(index)
        self._diffable = diffable
        self._diff_key = diff_key
        self._help_text = help_text
        self.index = index

    # Static Methods

    # Class Methods

    # Public Methods

    def get_difference_between_values(self, value_1=None, value_2=None):
        """
        Check to see whether the value given in value_1 is the same as value_2, and return a string representing
        the difference type if a difference is a found.
        :param value_1: The value to check for.
        :param value_2: The value to check against.
        :return: A string representing a difference type if the two values are different, otherwise None.
        """
        if value_1 != value_2:
            return "not-equal"
        else:
            return None

    def to_dict(self):
        """
        Create and return a dictionary representing the mapping that this type is attached to.
        :return: A dictionary representing the mapping that this type is attached to.
        """
        to_return = {"type": self.type}
        if self.index is not None:
            to_return["index"] = self.index
        return to_return

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def description(self):
        """
        Get a dictionary describing this data type.
        :return: a dictionary describing this data type.
        """
        return {
            "type": self.type,
            "description": self.help_text,
        }

    @property
    def diffable(self):
        """
        Get whether or not the value represented by this type is considered to be diffable for the
        Web Sight change tracking system.
        :return: whether or not the value represented by this type is considered to be diffable for
        the Web Sight change tracking system.
        """
        return self._diffable

    @property
    def diff_key(self):
        """
        Get whether or not the value represented by this type is included in the key used to
        retrieve the last instance of a model.
        :return: whether or not the value represented by this type is included in the key used to
        retrieve the last instance of a model.
        """
        return self._diff_key

    @property
    def help_text(self):
        """
        Get a description of the data stored in this type reference.
        :return: a description of the data stored in this type reference.
        """
        return self._help_text

    @property
    def type(self):
        """
        Get the Elasticsearch data type that this property represents.
        :return: The Elasticsearch data type that this property represents.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Representation and Comparison


class BaseComplexElasticsearchType(BaseElasticsearchType):
    """
    A base class for representing object types used by Web Sight Elasticsearch models.
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
    def description(self):
        to_return = self.to_dict()
        to_return["help_text"] = self.help_text
        return to_return

    @property
    def type(self):
        return "object"

    # Representation and Comparison
