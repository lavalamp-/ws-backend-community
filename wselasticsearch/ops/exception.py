# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class NoUpdatesError(BaseWsException):
    """
    An exception for denoting that an operation did not successfully update the expected amount
    of data.
    """

    _message = "No documents updated."
