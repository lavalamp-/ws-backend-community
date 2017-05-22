# -*- coding: utf-8 -*-
from __future__ import absolute_import


class BaseWsException(Exception):
    """
    A base exception class for all exceptions thrown by the Web Sight back-end.
    """

    _message = "Error thrown."

    def __init__(self, message=None):
        super(BaseWsException, self).__init__()
        if message is not None:
            self._message = "%s %s" % (self._message, message)

    @property
    def message(self):
        """
        Get the message that this exception contains.
        :return: the message that this exception contains.
        """
        return self._message

    def __repr__(self):
        return self.message

    def __str__(self):
        return repr(self)


class ValidationError(BaseWsException):
    """
    An error indicating that some form of validation has failed.
    """

    _message = "Validation failed."


class ConversionError(BaseWsException):
    """
    An error indicating that converting a value from one type to another failed.
    """

    _message = "Conversion failed."
