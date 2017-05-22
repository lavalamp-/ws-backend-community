# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class InvalidUrlError(BaseWsException):
    """
    An exception for denoting that a URL is not valid.
    """

    _message = "Invalid URL."


class InvalidScrapyResultError(BaseWsException):
    """
    An exception for denoting that a line of a Scrapy results file is not valid.
    """

    _message = "Invalid Scrapy result entry."


class UnsupportedScrapyResultError(BaseWsException):
    """
    An exception for denoting that the Scrapy result type found in a Scrapy result file is unsupported.
    """

    _message = "Scrapy result item not supported."


class UnknownPortError(BaseWsException):
    """
    An exception for denoting that a UrlWrapper does not know the port associated with its URL.
    """

    _message = "Unsure of URL port."
