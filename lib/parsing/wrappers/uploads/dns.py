# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseUploadWrapper
from lib import RegexLib


class DomainsTextFileWrapper(BaseUploadWrapper):
    """
    This is a wrapper class for text files uploaded by Web Sight users that contain information
    about domain names.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        self._rows = None
        self._errored_rows = None
        super(DomainsTextFileWrapper, self).__init__(*args, **kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _process_data(self):
        valid_rows = []
        invalid_rows = []
        for line in [x.strip() for x in self.wrapped_data.strip().split("\n")]:
            if RegexLib.domain_name_regex.match(line):
                valid_rows.append(line)
            else:
                invalid_rows.append(line)
        self._rows = valid_rows
        self._errored_rows = invalid_rows

    # Private Methods

    # Properties

    @property
    def errored_rows(self):
        """
        Get a list of the rows contained within the wrapped file that contained invalid domain names.
        :return: a list of the rows contained within the wrapped file that contained invalid domain names.
        """
        return self._errored_rows

    @property
    def rows(self):
        """
        Get a list of the valid rows contained within the wrapped file (ie: contain valid domain names).
        :return: a list of the valid rows contained within the wrapped file (ie: contain valid domain names).
        """
        return self._rows

    @property
    def wrapped_type(self):
        return "Domain Names Text File"

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)

