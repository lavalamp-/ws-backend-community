# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class NoKeyAvailableError(BaseWsException):
    """
    An exception for denoting that no usable key could be found for an Elasticsearch script.
    """
