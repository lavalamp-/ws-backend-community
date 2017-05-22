# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class NoResultFoundError(BaseWsException):
    """
    An exception for denoting that no result was found via a database query.
    """

    _message = "No result found."
