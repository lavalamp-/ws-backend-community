# -*- coding: utf-8 -*-
from __future__ import absolute_import

import uuid
import inspect
from django.http import Http404
from rest_framework import generics
import django.core.exceptions
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.db import models
from rest_framework import filters
from rest_framework.exceptions import ValidationError
import rest_framework.mixins

from .exception import FieldNotFound, OperationFailed
from lib import RegexLib, get_export_type_wrapper_map, ValidationHelper
import rest.responses


class BaseAPIViewMixin(object):
    """
    This is a base class for all view mixin classes used by Web Sight.
    """

    filter_backends = (filters.OrderingFilter,)
    _queried_fields = None

    def get_body_argument(self, key, required=True, replacement=""):
        if required:
            if key not in self.request.data:
                raise FieldNotFound("Field %s was not included in your request." % (key,))
            return self.request.data[key]
        else:
            return self.request.data.get(key, replacement)

    def raise_not_authorized(self):
        """
        Raise a not authorized error.
        :return: None
        """
        raise django.core.exceptions.PermissionDenied

    def validate_email(self, to_check):
        """
        Validate that the contents of to_check represent a valid email address.
        :param to_check: The string to check.
        :return: None
        """
        if not RegexLib.email_regex.match(to_check):
            raise ValidationError(
                "%s is not a valid email address."
                % (to_check,)
            )

    def validate_uuid(self, to_check):
        """
        Validate that the contents of to_check represent a valid UUID.
        :param to_check: The string to check.
        :return: None
        """
        if not RegexLib.uuid4_string_regex.match(to_check):
            raise ValidationError(
                "%s is not a valid UUID."
                % (to_check,)
            )

    def __get_queried_fields(self):
        """
        Get a list of the fields to query on the queried database model.
        :return: a list of the fields to query on the queried database model.
        """
        default_fields = list(self.serializer_class.Meta.fields)
        if not self.has_exclude_fields_argument and not self.has_include_fields_argument:
            return default_fields
        elif self.has_include_fields_argument:
            fields = []
            included_fields = [x.strip() for x in self.request.query_params[settings.INCLUDE_FIELDS_PARAM].split(",")]
            for included_field in included_fields:
                if included_field in default_fields:
                    fields.append(included_field)
        elif self.has_exclude_fields_argument:
            fields = []
            excluded_fields = [x.strip() for x in self.request.query_params[settings.EXCLUDE_FIELDS_PARAM].split(",")]
            for field in default_fields:
                if field not in excluded_fields:
                    fields.append(field)
        fields = list(set(fields))
        if len(fields) == 0:
            raise OperationFailed(detail="You must specify at least one valid field to query.")
        return fields

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
    def queried_fields(self):
        """
        Get a list of the fields to query on the queried database model.
        :return: a list of the fields to query on the queried database model.
        """
        if self._queried_fields is None:
            self._queried_fields = self.__get_queried_fields()
        return self._queried_fields


class OwnershipFilterMixin(BaseAPIViewMixin):
    """
    A mixin class that filters queried objects to only the objects owned by the requesting
    user.
    """

    def get_queryset(self):
        if self.request.user.is_superuser:
            return self._get_su_queryset()
        else:
            return self._get_user_queryset()

    def _get_su_queryset(self):
        raise NotImplementedError("Subclasses must implement this!")

    def _get_user_queryset(self):
        raise NotImplementedError("Subclasses must implement this!")


class ListMixin(BaseAPIViewMixin, generics.ListAPIView):
    """
    A bast ListView mixin for all Web sight REST ListAPIView handlers.
    """

    _exporter_map = None
    _export_argument = None
    pagination_enabled = True

    def list(self, request, *args, **kwargs):
        if self.has_presentation_argument:
            return rest.responses.WsPresentationResponse.from_model_api_view(self)
        elif self.has_export_argument:
            self.__validate_export_value()
            results = []
            query_results = self.get_queryset()
            for result in query_results:
                to_add = {}
                for field_name in self.queried_fields:
                    value = getattr(result, field_name)
                    if isinstance(value, uuid.UUID):
                        value = str(value)
                    elif isinstance(value, models.Model):
                        value = str(value.uuid)
                    to_add[field_name] = value
                results.append(to_add)
            return self.exporter_map[self.export_argument].get_django_response_from_dicts(results)
        else:
            to_return = super(BaseAPIViewMixin, self).list(request, *args, **kwargs)
            if hasattr(self, "filter_class"):
                to_return.data["filter_fields"] = self.filter_class.Meta.fields
            else:
                to_return.data["filter_fields"] = []
            if hasattr(self, "ordering_fields"):
                to_return.data["sortable_fields"] = list(self.ordering_fields)
            else:
                to_return.data["sortable_fields"] = []
            return to_return

    def __validate_export_value(self):
        """
        Ensure that the value in self.export_argument is a valid string to export via.
        :return: None
        """
        ValidationHelper.validate_in(to_check=self.export_argument, contained_by=self.exporter_map_keys)

    def paginate_queryset(self, queryset):
        if not self.pagination_enabled:
            self.paginator.page_size = 10000
        return super(ListMixin, self).paginate_queryset(queryset)

    @property
    def export_argument(self):
        """
        Get the export argument from the request's query string.
        :return: the export argument from the request's query string.
        """
        if self._export_argument is None:
            self._export_argument = self.request.query_params.get(settings.EXPORT_PARAM, "")
        return self._export_argument

    @property
    def exporter_map_keys(self):
        """
        Get a list of strings representing the valid export types supported by Web Sight.
        :return: a list of strings representing the valid export types supported by Web Sight.
        """
        return self.exporter_map.keys()

    @property
    def has_export_argument(self):
        """
        Get whether or not the request has an export argument.
        :return: whether or not the request has an export argument.
        """
        return settings.EXPORT_PARAM in self.request.query_params

    @property
    def has_presentation_argument(self):
        """
        Get whether or not the request has the presentation argument.
        :return: whether or not the request has the presentation argument.
        """
        return settings.PRESENTATION_PARAM in self.request.query_params

    @property
    def exporter_map(self):
        """
        Get a dictionary that maps export types to the classes that can handle exporting data to a file
        of the given type.
        :return: A dictionary that maps export types to the classes that can handle exporting data to a file
        of the given type.
        """
        if self._exporter_map is None:
            self._exporter_map = get_export_type_wrapper_map()
        return self._exporter_map


class ListChildMixin(BaseAPIViewMixin):
    """
    A base ListAPIView mixin for all Web Sight REST ListAPIView handlers that rely on retrieving
    results based on a parent class.
    """

    # Class Members

    _parent_object = None
    _exporter_map = None
    _export_argument = None
    pagination_enabled = True

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def get_queryset(self):
        """
        Get the data meant to be returned by this API view.
        :return: The data meant to be returned by this API view.
        """
        if self.__in_get_schema_call():
            return self.__get_schema_call_queryset()
        else:
            return getattr(self.parent_object, self.child_attribute).all()

    def list(self, request, *args, **kwargs):
        if self.has_presentation_argument:
            return rest.responses.WsPresentationResponse.from_model_api_view(self)
        elif self.has_export_argument:
            self.__validate_export_value()
            results = []
            query_results = self.get_queryset()
            if len(query_results) == 0:
                raise Http404()
            for result in query_results:
                to_add = {}
                for field_name in self.queried_fields:
                    value = getattr(result, field_name)
                    if isinstance(value, uuid.UUID):
                        value = str(value)
                    elif isinstance(value, models.Model):
                        value = str(value.uuid)
                    to_add[field_name] = value
                results.append(to_add)
            return self.exporter_map[self.export_argument].get_django_response_from_dicts(results)
        else:
            to_return = super(ListChildMixin, self).list(request, *args, **kwargs)
            if hasattr(self, "filter_class"):
                to_return.data["filter_fields"] = self.filter_class.Meta.fields
            else:
                to_return.data["filter_fields"] = []
            if hasattr(self, "ordering_fields"):
                to_return.data["sortable_fields"] = list(self.ordering_fields)
            else:
                to_return.data["sortable_fields"] = []
            return to_return

    def paginate_queryset(self, queryset):
        if not self.pagination_enabled:
            self.paginator.page_size = 10000
        return super(ListChildMixin, self).paginate_queryset(queryset)

    # Protected Methods

    # Private Methods

    def __get_parent_object(self, pk):
        """
        Get the parent object whose children are being queried.
        :param pk: The primary key of the parent object.
        :return: The parent object whose children are being queried.
        """
        parent_class = self.parent_class
        return get_object_or_404(parent_class, pk=pk)

    def __get_schema_call_queryset(self):
        """
        Get a queryset containing instances of the child class without querying based on a
        parent object. This method should only be invoked in calls to get_schema_fields, as this is
        a work-around to the error that is thrown when accessing parent_object from within the
        get_schema_fields call.
        :return: A queryset containing instances of the child class.
        """
        rel = getattr(self.parent_class, self.child_attribute)
        return rel.rel.related_model.objects.all()

    def __in_get_schema_call(self):
        """
        Check to see whether or not this method is currently being called from within a call
        to the get_schema_fields method.
        :return: True if this method is currently being called from within a call to the
        get_schema_fields, False otherwise.
        """
        return any([x[3] == "get_schema_fields" for x in inspect.stack()])

    def __validate_export_value(self):
        """
        Ensure that the value in self.export_argument is a valid string to export via.
        :return: None
        """
        ValidationHelper.validate_in(to_check=self.export_argument, contained_by=self.exporter_map_keys)

    # Properties

    @property
    def child_attribute(self):
        """
        Get a string representing the class attribute on self.parent_class that will
        retrieve the necessary child data.
        :return: a string representing the class attribute on self.parent_class
        that will retrieve the necessary child data.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def export_argument(self):
        """
        Get the export argument from the request's query string.
        :return: the export argument from the request's query string.
        """
        if self._export_argument is None:
            self._export_argument = self.request.query_params.get(settings.EXPORT_PARAM, "")
        return self._export_argument

    @property
    def exporter_map_keys(self):
        """
        Get a list of strings representing the valid export types supported by Web Sight.
        :return: a list of strings representing the valid export types supported by Web Sight.
        """
        return self.exporter_map.keys()

    @property
    def has_export_argument(self):
        """
        Get whether or not the request has an export argument.
        :return: whether or not the request has an export argument.
        """
        return settings.EXPORT_PARAM in self.request.query_params

    @property
    def has_presentation_argument(self):
        """
        Get whether or not the request has the presentation argument.
        :return: whether or not the request has the presentation argument.
        """
        return settings.PRESENTATION_PARAM in self.request.query_params

    @property
    def exporter_map(self):
        """
        Get a dictionary that maps export types to the classes that can handle exporting data to a file
        of the given type.
        :return: A dictionary that maps export types to the classes that can handle exporting data to a file
        of the given type.
        """
        if self._exporter_map is None:
            self._exporter_map = get_export_type_wrapper_map()
        return self._exporter_map

    @property
    def parent_class(self):
        """
        Get the class of the parent object that this child view is querying against.
        :return: The class of the parent object that this child view is querying against.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def parent_object(self):
        """
        Get the parent model object that owns the queried resources.
        :return: the parent model object that owns the queried resources.
        """
        if self._parent_object is None:
            self._parent_object = self.__get_parent_object(self.kwargs["pk"])
        return self._parent_object

    # Representation and Comparison


class ListCreateChildMixin(ListChildMixin):
    """
    This is a base APIView mixin for views that want to both list and create new child objects for
    parent objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def get_serializer(self, *args, **kwargs):
        if "data" in kwargs:
            mapping = self._get_parent_mapping()
            kwargs["data"][mapping.keys()[0]] = mapping[mapping.keys()[0]].uuid
        return super(ListCreateChildMixin, self).get_serializer(*args, **kwargs)

    # Protected Methods

    def _get_parent_mapping(self):
        """
        Get a dictionary that maps an attribute on the newly-created object to the necessary key
        to establish the relationship to the requested parent.
        :return: A dictionary that maps an attribute on the newly-created object to the necessary key
        to establish the relationship to the requested parent.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    # Properties

    # Representation and Comparison


class WsRetrieveMixin(generics.RetrieveAPIView):
    """
    This is a mixin class for handling the retrieval of specific instances of Django models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def retrieve(self, request, *args, **kwargs):
        if self.has_presentation_argument:
            return rest.responses.WsPresentationResponse.from_model_api_view(self)
        else:
            to_return = super(WsRetrieveMixin, self).retrieve(request, *args, **kwargs)
            if hasattr(self, "queried_fields"):
                for k in to_return.data:
                    if k not in self.queried_fields:
                        to_return.data.pop(k)
            return to_return

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def has_presentation_argument(self):
        """
        Get whether or not the request has the presentation argument.
        :return: whether or not the request has the presentation argument.
        """
        return settings.PRESENTATION_PARAM in self.request.query_params

    # Representation and Comparison


class WsUpdateMixin(generics.UpdateAPIView):
    """
    This is a mixin class for handling the updating of specific instances of Django models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class WsDestroyMixin(generics.DestroyAPIView):
    """
    This is a mixin class for handling the deletion of specific instances of Django models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
