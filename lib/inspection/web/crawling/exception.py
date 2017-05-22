# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class UnsupportedItemWriteError(BaseWsException):
    """
    An exception for denoting that a given Scrapy item is not supported by the local file
    writer pipeline.
    """

    _message = "Item class not supported."
