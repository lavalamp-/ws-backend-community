# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class TooManyEsResultsError(BaseWsException):
    """
    This is an exception for denoting that too many results were returned by an Elasticsearch query.
    """

    _message = "Too many results returned."
