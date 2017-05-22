# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class BulkOperationNotSupportedError(BaseWsException):
    """
    An exception for denoting that a given Elasticsearch bulk operation is not supported.
    """

    _message = "Bulk operation not supported."


class EmptyBulkQueueError(BaseWsException):
    """
    An exception for denoting that the bulk queue for a BulkElasticsearchQuery is currently empty.
    """

    _message = "No operations currently in queue."
