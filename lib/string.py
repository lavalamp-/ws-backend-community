# -*- coding: utf-8 -*-
from __future__ import absolute_import
import re


class StringHelper(object):
    """
    A helper class for manipulating strings.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def to_dash_case(to_convert):
        """
        Convert the contents of to_convert to dash case (e.g. MyClass -> my-class).
        :param to_convert: The string to convert.
        :return: The contents of to_convert in dash case.
        """
        if to_convert.isupper():
            return to_convert
        else:
            return (
                to_convert[0].lower() +
                re.sub(r'([A-Z])',
                       lambda letter: "-" + letter.group(0).lower(), to_convert[1:]
                       )
            )

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

