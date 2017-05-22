# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework.exceptions import APIException


class FieldNotFound(APIException):
    """
    This is an API exception for denoting that a required field was not found in an API request.
    """

    status_code = 400
    default_detail = "A required field was not found in your request."
    default_code = "field_not_found"


class OperationNotAllowed(APIException):
    """
    This is an API exception for denoting that an operation is not allowed.
    """

    status_code = 400
    default_detail = "You are not allowed to perform that operation."
    default_code = "op_not_allowed"


class OperationFailed(APIException):
    """
    This is an API exception for denoting that an operation has failed.
    """

    status_code = 400
    default_detail = "An operation has failed."
    default_code = "op_failed"
