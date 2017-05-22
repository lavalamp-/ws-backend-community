# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class NoMappedParentClassFoundError(BaseWsException):
    """
    This is an exception for denoting that no database-mapped parent class was found.
    """

    _message = "No mapped parent class found."

