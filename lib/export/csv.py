# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseExporter


class CsvExporter(BaseExporter):
    """
    This class contains methods for exporting data to CSV files.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def get_content_type():
        return "text/csv"

    @staticmethod
    def get_content_type_mapping():
        return "csv"

    @staticmethod
    def get_extension():
        return "csv"

    # Class Methods

    @classmethod
    def export_data(cls, data):
        to_return = []
        keys = []
        for row in data:
            keys.extend(row.keys())
        keys = sorted(list(set(keys)))
        to_return.append(", ".join(keys))
        for row in data:
            row_entries = []
            for key in keys:
                column_data = "%s" % row.get(key, "N/A")
                column_data = column_data.replace(",", ".").replace("\r", "").replace("\n", "")
                row_entries.append(column_data)
            to_return.append(", ".join(row_entries))
        return "\n".join(to_return)

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
