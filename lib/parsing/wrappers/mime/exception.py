# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class InvalidMimeStringError(BaseWsException):
    """
    An exception for denoting that a MIME string was invalid.
    """

    _message = "Invalid MIME string."


class MarkupAttributeNotFoundError(BaseWsException):
    """
    An exception for denoting that an HTML tag attribute was not found.
    """

    _message = "Markup tag attribute was not found."
