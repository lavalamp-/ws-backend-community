# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..filesystem import FilesystemHelper
from ..introspection import WsIntrospectionHelper


def get_export_type_wrapper_map():
    """
    Get a dictionary that maps export type strings to exporter classes that export data to
    the given file type.
    :return: A dictionary that maps export type strings to exporter classes that export data to
    the given file type.
    """
    class_tuples = WsIntrospectionHelper.get_export_type_wrapper_classes()
    return {exporter_class.get_content_type_mapping(): exporter_class for class_name, exporter_class in class_tuples}


class BaseExporter(object):
    """
    This is a base class for all exporter classes.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def get_content_type():
        """
        Get a string representing the content type exported by this class.
        :return: A string representing the content type exported by this class.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @staticmethod
    def get_extension():
        """
        Get a string representing the file extension for the file type exported by this class.
        :return: A string representing the file extension for the file type exported by this class.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @staticmethod
    def get_content_type_mapping():
        """
        Get a string representing the content type that this class is meant to export.
        :return: A string representing the content type that this class is meant to export.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Class Methods

    @classmethod
    def get_django_response(cls, data):
        """
        Create and return a Django file response wrapping the given data.
        :param data: The data to parse via this exporter.
        :return: A Django file response for serving up the given data exported through this exporter's
        file type.
        """
        from rest.responses import WsFileResponse
        file_content = cls.export_data(data)
        return WsFileResponse(
            file_contents=file_content,
            content_type=cls.get_content_type(),
            file_name="exported_data.%s" % (cls.get_extension(),),
            status=200,
        )

    @classmethod
    def get_django_response_from_dicts(cls, dicts):
        """
        Create and return a Django file response wrapping the data found in the given list of
        dictionaries.
        :param dicts: A list of dictionaries to process.
        :return: A Django fil response for serving up the given data exported through this exporter's
        file type.
        """
        return cls.get_django_response(dicts)

    @classmethod
    def get_django_response_from_elasticsearch_response(cls, response):
        """
        Create and return a Django file response wrapping the data found in the given Elasticsearch query
        response.
        :param response: An Elasticsearch query response.
        :return: A Django file response for serving up the given data exported through this exporter's
        file type.
        """
        return cls.get_django_response([x["_source"] for x in response.results])

    @classmethod
    def export_data_to_file(cls, data=None, file_path=None):
        """
        Create and return the file contents for a file of this exporter type containing the contents
        of the given data.
        :param data: A list of dictionaries to export data through.
        :param file_path: The file path where the file data is stored.
        :return: None.
        """
        data = cls.export_data(data)
        FilesystemHelper.write_to_file(data=data, file_path=file_path, write_mode="wb+")

    @classmethod
    def export_data(cls, data):
        """
        Export the contents of the given data to a raw file blob containing the file contents for
        the type of file this exporter handles.
        :param data: The data to export.
        :return: A string containing the raw data of the exported file type.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def content_type(self):
        """
        Get a string representing the content type exported by this class.
        :return: a string representing the content type exported by this class.
        """
        return self.__class__.get_content_type()

    @property
    def content_type_mapping(self):
        """
        Get a string representing the content type that this class is meant to export.
        :return: a string representing the content type that this class is meant to export.
        """
        return self.__class__.get_content_type_mapping()

    @property
    def extension(self):
        """
        Get a string representing the file type extension for the file type exported by this class.
        :return: a string representing the file type extension for the file type exported by this class.
        """
        return self.__class__.get_extension()

    # Representation and Comparison
