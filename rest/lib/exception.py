# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db import IntegrityError
from rest_framework.exceptions import ValidationError, APIException
from rest_framework.response import Response
from rest_framework.views import exception_handler


def web_sight_exception_handler(exc, context):
    """
    This is a custom Django exception handler that handles all exceptions thrown by the Web Sight REST
    API.
    :param exc: The exception that was thrown.
    :param context: The context in which the exception was thrown.
    :return: A response to return to the requesting user.
    """
    if isinstance(exc, IntegrityError):
        return handle_integrity_error(exc, context)
    elif isinstance(exc, ValidationError):
        return handle_validation_error(exc, context)
    elif isinstance(exc, WsRestNonFieldException):
        return handle_non_field_error(exc, context)
    elif isinstance(exc, APIException):
        return handle_api_exception(exc, context)
    else:
        return None


def handle_api_exception(exc, context):
    """
    Handle the given APIException.
    :param exc: The exception that was thrown.
    :param context: The context in which the exception was thrown.
    :return: A Django Response object.
    """
    response = exception_handler(exc, context)
    response.data = {
        "status_code": response.status_code,
        "message": "Exception thrown",
        "detail": exc.detail,
        "error_fields": [],
    }
    return response


def handle_integrity_error(exc, context):
    """
    Handle the given IntegrityError and return a response.
    :param exc: The exception that was thrown.
    :param context: The context in which the exception was thrown.
    :return: A Django Response object.
    """
    response = Response(status=409)
    response.data = {
        "status_code": 409,
        "message": "That object already exists.",
        "detail": exc.message.split("\n")[1],
        "error_fields": [],
    }
    return response


def handle_validation_error(exc, context):
    """
    Handle the given ValidationError and return a response.
    :param exc: The exception that was thrown.
    :param context: The context in which the exception was thrown.
    :return: A Django Response object.
    """
    response = exception_handler(exc, context)
    response.status_code = 400
    response.data = {
        "status_code": 400,
        "message": "Invalid input received.",
        "detail": "There was an error with the data that you submitted. Please check your input and try again.",
        "error_fields": exc.get_full_details(),
    }
    return response


def handle_non_field_error(exc, context):
    """
    Handle the given WsRestNonFieldException and return a response.
    :param exc: The exception that was thrown.
    :param context: The context in which the exception was thrown.
    :return: A Django Response object.
    """
    response = exception_handler(exc, context)
    response.status_code = 400
    response.data = {
        "status_code": 400,
        "message": "Invalid input received.",
        "detail": exc.detail,
        "error_fields": [],
    }
    return response


class WsBaseApiError(object):
    """
    This is a base exception for all errors that are thrown by the Web Sight REST API.
    """

    #These are the possible error types

    DEFAULT_ERROR_TYPE = "default"
    NON_FIELD_ERROR_TYPE = "non_field_error"
    FIELD_ERROR_TYPE = "field_error"

    def __init__(self, error_message="Unknown error", error_type="default"):
        self.error_message = error_message
        self.error_type = error_type

    def to_dict(self):
        self_dict = {
            "error_message": self.error_message,
            "error_type": self.error_type
        }
        return self_dict


class WsApiFieldError(WsBaseApiError):
    """
    This is an exception for errors that are related to specific fields.
    """

    def __init__(self, field=None, **kwargs):
        kwargs["error_type"] = self.FIELD_ERROR_TYPE
        super(WsApiFieldError, self).__init__(**kwargs)
        self.field = field

    def to_dict(self):
        self_dict = super(WsApiFieldError, self).to_dict()
        self_dict["field"] = self.field
        return self_dict


class WsApiNonFieldError(WsBaseApiError):
    """
    This is an exception for errors that are not related to specific fields.
    """

    def __init__(self, **kwargs):
        kwargs["error_type"] = self.NON_FIELD_ERROR_TYPE
        super(WsApiNonFieldError, self).__init__(**kwargs)


class WsBaseRestException(APIException):
    """
    This is the base rest exception, subclassed to make things easier
    """

    def __init__(self, error_message, error_type):
        super(WsBaseRestException, self).__init__(error_message, error_type)
        self.errors_dict = {
            "errors": [],
        }
        self.status_code = 400

    def add_error(self, error_message, error_type, field=None):
        """
        This will add an error to the exception, based on the provided input
        :param error_message: The message of the error
        :param error_type: The type of the error, check WsBaseExceptionError for possible types
        :param field: The optional field that this error is related to
        """
        if error_type == WsBaseApiError.FIELD_ERROR_TYPE:
            error = WsApiFieldError(error_message=error_message, field=field)
        elif error_type == WsBaseApiError.NON_FIELD_ERROR_TYPE:
            error = WsApiNonFieldError(error_message=error_message)
        else:
            error = WsBaseApiError(error_message=error_message, error_type=error_type)
        self.errors_dict["errors"].append(error.to_dict())

    def add_data(self, key, value):
        """ This will add a random key and value to the exception structure """
        self.errors_dict[key] = value

    def require_recaptcha(self):
        """ Sets the data attribute, that will require recaptcha on the front end"""
        self.add_data("recaptcha", True)

    def to_json(self):
        return self.errors_dict


class WsRestFieldException(WsBaseRestException):
    """
    This exception is raised for a specific field
    """

    def __init__(self, error_message, field):
        super(WsRestFieldException, self).__init__(error_message, WsBaseApiError.FIELD_ERROR_TYPE)
        self.add_error(error_message, WsBaseApiError.FIELD_ERROR_TYPE, field)


class WsRestNonFieldException(WsBaseRestException):
    """
    This exception is raised for errors not related to a field
    """

    def __init__(self, error_message):
        super(WsRestNonFieldException, self).__init__(error_message, WsBaseApiError.NON_FIELD_ERROR_TYPE)
        self.add_error(error_message, WsBaseApiError.NON_FIELD_ERROR_TYPE)

