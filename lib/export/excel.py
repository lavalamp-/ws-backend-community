# -*- coding: utf-8 -*-
from __future__ import absolute_import

from StringIO import StringIO
import xlsxwriter
import logging

from .base import BaseExporter
from ..conversion import ConversionHelper
from ..filesystem import FilesystemHelper

logger = logging.getLogger(__name__)


class ExcelExporter(BaseExporter):
    """
    This class contains methods for creating Excel workbooks based on data contained within
    Web Sight.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def add_cell_format_to_workbook(workbook):
        """
        Add the default cell format to the specified workbook and return it.
        :param workbook: The workbook to add the format to.
        :return: The newly-created format.
        """
        return workbook.add_format({
            "font_color": "#788886",
        })

    @staticmethod
    def add_first_cell_format_to_workbook(workbook):
        """
        Add the default first cell format to the specified workbook and return it.
        :param workbook: The workbook to add the format to.
        :return: The newly-created format.
        """
        return workbook.add_format({
            "font_color": "#788886",
            "align": "center",
            "bold": True,
        })

    @staticmethod
    def add_first_header_cell_format_to_workbook(workbook):
        """
        Add the default first header cell format to the specified workbook and return it.
        :param workbook: The workbook to add the format to.
        :return: The newly-created format.
        """
        return workbook.add_format({
            "bold": True,
            "font_color": "#E8F1F1",
            "bg_color": "#4FC8EF",
            "bottom": 2,
            "border_color": "#BBBDC0",
            "align": "center",
        })

    @staticmethod
    def add_header_format_to_workbook(workbook):
        """
        Add the default header format to the specified workbook and return it.
        :param workbook: The workbook to add the format to.
        :return: The newly-created format.
        """
        return workbook.add_format({
            "bold": True,
            "font_color": "#E8F1F1",
            "bg_color": "#4FC8EF",
            "bottom": 2,
            "border_color": "#BBBDC0",
        })

    @staticmethod
    def add_sheet_to_workbook(workbook=None, name=None, data=None):
        """
        Add a worksheet to the given workbook containing the specified data and return it.
        :param workbook: The workbook to add a sheet to.
        :param name: The name to give the worksheet.
        :param data: The data to write to the worksheet. This should be a two-dimensional list.
        :return: The newly-created worksheet.
        """
        worksheet = workbook.add_worksheet(name)
        column_widths = [5]
        keys = []
        for row in data:
            keys.extend(row.keys())
        keys = list(set(keys))
        for key in keys:
            width = 0
            for row in data:
                if key not in row:
                    row_string = "N/A"
                elif isinstance(row[key], str):
                    row_string = ConversionHelper.string_to_unicode(row[key])
                elif isinstance(row[key], unicode):
                    row_string = row[key]
                else:
                    row_string = unicode(row[key])
                width = max(len(row_string), width)
                width = max(width, len(key))
            column_widths.append(width)
        logger.debug(
            "In ExcelExportHelper, column widths are %s."
            % (column_widths,)
        )
        header_format = ExcelExporter.add_header_format_to_workbook(workbook)
        first_header_cell_format = ExcelExporter.add_first_header_cell_format_to_workbook(workbook)
        first_cell_format = ExcelExporter.add_first_cell_format_to_workbook(workbook)
        cell_format = ExcelExporter.add_cell_format_to_workbook(workbook)
        for column_index, width in enumerate(column_widths):
            worksheet.set_column(column_index, column_index, width)
        worksheet.write(0, 0, "#", first_header_cell_format)
        for key_index, key in enumerate(keys):
            key_index += 1
            worksheet.write(0, key_index, key, header_format)
        for row_index, row in enumerate(data):
            row_index += 1
            worksheet.write(row_index, 0, row_index, first_cell_format)
            for column_index, column_key in enumerate(keys):
                if column_key in row:
                    column_data = "%s" % (row[column_key],)
                else:
                    column_data = "N/A"
                worksheet.write(row_index, column_index + 1, column_data, cell_format)
        return worksheet

    @staticmethod
    def create_excel_workbook(file_path):
        """
        Create an Excel workbook at the specified file path.
        :param file_path: The path where the workbook should be created.
        :return: The workbook object.
        """
        return xlsxwriter.Workbook(file_path)

    @staticmethod
    def get_content_type_mapping():
        return "xlsx"

    @staticmethod
    def get_content_type():
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    @staticmethod
    def get_extension():
        return "xlsx"

    # Class Methods

    @classmethod
    def export_data(cls, data):
        output_io = StringIO()
        workbook = ExcelExporter.create_excel_workbook(output_io)
        ExcelExporter.add_sheet_to_workbook(
            workbook=workbook,
            name="Exported Data",
            data=data,
        )
        workbook.close()
        return output_io.getvalue()

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
