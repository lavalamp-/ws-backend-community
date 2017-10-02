# -*- coding: utf-8 -*-
from __future__ import absolute_import
from datetime import datetime, timedelta
from dateutil.tz import tzoffset


class DatetimeHelper(object):
    """
    A helper class for manipulating Python datetime objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def minutes_ago(count):
        """
        Get a datetime from the specified number of minutes ago.
        :param count: The number of minutes ago the datetime should represent.
        :return: A datetime from the specified number of minutes ago.
        """
        return DatetimeHelper.now() - timedelta(minutes=count)

    @staticmethod
    def minutes_from_now(count):
        """
        Get a datetime from the specified number of minutes in the future.
        :param count: The number of minutes in the future the datetime should represent.
        :return: A datetime from the specified number of minutes in the future.
        """
        return DatetimeHelper.now() + timedelta(minutes=count)

    @staticmethod
    def seconds_from_now(count):
        """
        Get a datetime from the specified number of seconds in the future.
        :param count: The number of seconds in the future to get the datetime at.
        :return: A datetime from the specified number of seconds in the future.
        """
        return DatetimeHelper.now() + timedelta(seconds=count)

    @staticmethod
    def now():
        """
        Get the current datetime.
        :return: The current datetime.
        """
        return datetime.utcnow().replace(tzinfo=tzoffset(None, 0))

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

