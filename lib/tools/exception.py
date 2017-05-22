# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib.exception import BaseWsException


class NotSupportedError(BaseWsException):
    """
    An exception for denoting that the requested configuration of a inspection class is
    not supported.
    """

    _message = "Configuration not supported."


class ToolConfigNotFoundError(BaseWsException):
    """
    An exception for denoting that a tool's configuration was not found.
    """

    _message = "Tool configuration not found."


class ToolNotFoundError(BaseWsException):
    """
    An exception for denoting that a tool is not found on the underlying host.
    """

    _message = "Tool not found."


class ToolNotReadyError(BaseWsException):
    """
    An exception for denoting that a tool wrapped by an InspectionToolWrapper implementation
    is not ready yet.
    """

    _message = "Tool not ready."


class ToolResultsNotReadyError(BaseWsException):
    """
    An exception for denoting that the results of running a tool are not yet ready.
    """

    _message = "Results not yet ready."


class SslCertificateRetrievalFailedError(BaseWsException):
    """
    An exception for denoting that attempting to retrieve an SSL certificate failed.
    """

    _message = "SSL certificate retrieval failed."
