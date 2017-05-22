# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class SslCertificateRetrievalFailedError(BaseWsException):
    """
    An exception for denoting that attempting to retrieve an SSL certificate failed.
    """

    _message = "SSL certificate retrieval failed."
