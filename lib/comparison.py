# -*- coding: utf-8 -*-
from __future__ import absolute_import

import editdistance


class ComparisonHelper(object):
    """
    This class contains helper methods for comparing various types of data against
    one another, or even across data types.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def compare_strings_by_edit_distance(first=None, second=None):
        """
        Get the edit distance between the two strings passed to this method.
        :param first: The first string to compare.
        :param second: The second string to compare.
        :return: A number representing the edit distance between the two strings passed
        as arguments to this method.
        """
        return editdistance.eval(first, second)

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)
