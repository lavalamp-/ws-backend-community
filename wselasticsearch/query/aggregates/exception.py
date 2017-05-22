# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class TooManyCountError(BaseWsException):
    """
    This is an exception for denoting that too many result buckets were returned in an aggregate intended to
    count a single term.
    """

    _message = "Too many results returned for count."


class InvalidRangeError(BaseWsException):
    """
    This is an exception for denoting that a range aggregate received invalid input for adding ranges.
    """

    _message = "Too few steps."
