# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework.schemas import SchemaGenerator


class WebSightSchemaGenerator(SchemaGenerator):
    """
    This is a custom schema generator that populates the response types for schema definitions
    created by the default SchemaGenerator.
    """

    def get_link(self, path, method, view):
        """
        Override the default functionality for get_link to populate the contents with the data
        associated with the response type.
        :param path: The path of the view to populate.
        :param method: The method of the view to populate.
        :param view: The view to populate the schema based on.
        :return: The schema associated with the given path, method, and view.
        """
        return super(WebSightSchemaGenerator, self).get_link(path, method, view)
