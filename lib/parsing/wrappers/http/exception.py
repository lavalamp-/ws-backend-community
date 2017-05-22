# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class InvalidReferenceError(BaseWsException):
    """
    An exception for denoting that the contents of an HttpReferenceWrapper are not usable for a UrlWrapper.
    """

    _message = "Invalid reference contents."
