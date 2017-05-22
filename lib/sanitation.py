# -*- coding: utf-8 -*-
from __future__ import absolute_import

import re
import logging

logger = logging.getLogger(__name__)


class SanitationHelper(object):
    """
    This class contains helper methods for sanitizing strings.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def clean_list_of_virtual_hosts(to_process):
        """
        Clean the contents of the list found in to_process to remove any virtual host
        names that are obviously not possible to use as virtual host names.
        :param to_process: A list of strings to process.
        :return: The cleaned version of to_process.
        """
        to_return = filter(lambda x: "*" not in x, to_process)
        return [x.strip() for x in to_return]

    @staticmethod
    def remove_html_entities_from_string(to_process):
        """
        Remove all HTML entity codes from the given string.
        :param to_process: The string to sanitize.
        :return: to_process with all HTML entity codes removed.
        """
        to_process = re.sub("&[a-zA-Z]{1,5};", "", to_process)
        to_process = re.sub("&#x[A-Za-z0-9]{1,7};", "", to_process)
        to_process = re.sub("&#\d{1,7};", "", to_process)
        return to_process

    @staticmethod
    def truncate_at_last_instance(to_process=None, trunc_char=None):
        """
        Truncate the contents of to_process at the final instance of the given character.
        :param to_process: The string to process.
        :param trunc_char: The character to find.
        :return: The contents of to_process but truncated at the final instance of
        the given character.
        """
        if trunc_char not in to_process:
            logger.warning(
                "Attempted to truncate string of %s at character %s, but character was not found."
                % (to_process, trunc_char)
            )
            return to_process
        return to_process[:to_process.rfind(trunc_char)+1]

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)
