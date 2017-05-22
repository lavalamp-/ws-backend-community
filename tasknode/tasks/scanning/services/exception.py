# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class UnknownProtocolError(BaseWsException):
    """
    An exception for denoting that a network protocol is not known.
    """

    _message = "Unknown protocol"


class UnsupportedProtocolError(BaseWsException):
    """
    An exception for denoting that a network protocol is not supported.
    """

    _message = "Protocol not supported."
