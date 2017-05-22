# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import BaseWsException


class FingerprintingFailedError(BaseWsException):
    """
    An exception for denoting that fingerprinting a remote service has failed.
    """

    _message = "Fingerprinting failed."
