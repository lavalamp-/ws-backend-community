# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers

from django.conf import settings

from rest.views.exception import OperationFailed


class WsBaseSerializerMixin(object):
    """
    This is a mixin class for all of the serializers used by Web Sight's REST API.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        super(WsBaseSerializerMixin, self).__init__(*args, **kwargs)
        if self.request.method == "GET":
            self.__set_fields_by_query_params()

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    def __set_fields_by_query_params(self):
        """
        Set the fields on this serializer class to match the fields either included or excluded by
        query string parameters.
        :return: None
        """
        if not self.has_exclude_fields_argument and not self.has_include_fields_argument:
            return
        elif self.has_include_fields_argument:
            included_fields = [x.strip() for x in self.request.query_params[settings.INCLUDE_FIELDS_PARAM].split(",")]
            existing_keys = set(self.fields.keys())
            for existing_key in existing_keys:
                if existing_key not in included_fields:
                    self.fields.pop(existing_key)
        elif self.has_exclude_fields_argument:
            excluded_fields = [x.strip() for x in self.request.query_params[settings.EXCLUDE_FIELDS_PARAM].split(",")]
            for excluded_field in excluded_fields:
                if excluded_field in self.fields:
                    self.fields.pop(excluded_field)
        if len(self.fields) == 0:
            raise OperationFailed(detail="You must specify at least one valid field to query.")

    # Properties

    @property
    def has_exclude_fields_argument(self):
        """
        Get whether or not the request has the exclude fields argument.
        :return: whether or not the request has the exclude fields argument.
        """
        return settings.EXCLUDE_FIELDS_PARAM in self.request.query_params

    @property
    def has_include_fields_argument(self):
        """
        Get whether or not the request has the include fields argument.
        :return: whether or not the request has the include fields argument.
        """
        return settings.INCLUDE_FIELDS_PARAM in self.request.query_params

    @property
    def request(self):
        """
        Get the request that resulted in this serializer being invoked.
        :return: the request that resulted in this serializer being invoked.
        """
        return self.context["request"]

    @property
    def requesting_user(self):
        """
        Get the user that issued this request.
        :return: the user that issued this request.
        """
        return self.request.user

    # Representation and Comparison


class WsBaseModelSerializer(WsBaseSerializerMixin, serializers.ModelSerializer):
    """
    This is the base serializer for all Web Sight REST API serializers.
    """
