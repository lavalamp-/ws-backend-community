# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseSourceElasticsearchScript
from lib import DatetimeHelper


class KeyValueUpdateElasticsearchScript(BaseSourceElasticsearchScript):
    """
    This is a script class that updates a given model key to a value.
    """

    # Class Members

    # Instantiation

    def __init__(self, key=None, value=None, **kwargs):
        super(KeyValueUpdateElasticsearchScript, self).__init__(**kwargs)
        self.add_equals(key=key, value=value)

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class NowUpdateElasticsearchScript(KeyValueUpdateElasticsearchScript):
    """
    This is a script class that updates a given key to the current datetime.
    """

    # Class Members

    # Instantiation

    def __init__(self, **kwargs):
        kwargs["value"] = DatetimeHelper.now()
        super(NowUpdateElasticsearchScript, self).__init__(**kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
