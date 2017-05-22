# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from .base import BaseWrapper

logger = logging.getLogger(__name__)


class ZmapCsvWrapper(BaseWrapper):
    """
    This class is meant to wrap the contents of Zmap CSV output files.
    """

    # Class Members

    _scan_results = None

    # Instantiation

    def __init__(self, *args, **kwargs):
        """
        Initialize this ZmapCsvWrapper to ensure that its scan_results dictionary is
        initially empty.
        :param args: Positional arguments.
        :param kwargs: Keyword arguments.
        """
        self._scan_results = {}
        super(ZmapCsvWrapper, self).__init__(*args, **kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _process_data(self):
        split_data = [x.strip() for x in self.wrapped_data.strip().split("\n")]
        logger.debug(
            "Now processing a Zmap CSV file with %s total lines."
            % (len(split_data),)
        )
        header_row = split_data[0]
        headers = [x.strip() for x in header_row.split(",")]
        data_rows = split_data[1:]
        for data_row in data_rows:
            self.__process_data_row(headers=headers, data_row=data_row)

    # Private Methods

    def __process_data_row(self, headers=None, data_row=None):
        """
        Process the given data row from the wrapped CSV file and add its contents to the
        data already stored within this class.
        :param headers: An ordered list of the headers from the CSV file.
        :param data_row: A string representing a single data row in the CSV file.
        :return: None
        """
        row_split = [x.strip() for x in data_row.split(",")]
        saddr_index = headers.index("saddr")
        saddr = row_split[saddr_index]
        result = {}
        for index, header in enumerate(headers):
            result[header] = row_split[index]
        self._scan_results[saddr] = result

    # Properties

    @property
    def scan_results(self):
        """
        Get a dictionary mapping IP addresses to the data contained within the rows of the
        referenced CSV file.
        :return: A dictionary mapping IP addresses to the data contained within the rows of the
        referenced CSV file.
        """
        return self._scan_results

    @property
    def wrapped_type(self):
        return "Zmap CSV Output File"

    # Representation and Comparison
