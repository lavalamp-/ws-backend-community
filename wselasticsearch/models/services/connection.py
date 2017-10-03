# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import DatetimeHelper
from .base import BaseNetworkServiceScanModel
from ..types import *


class NetworkServiceLivenessModel(BaseNetworkServiceScanModel):
    """
    This is an Elasticsearch model for representing the results of a service liveness check.
    """

    # Class Members

    is_alive = BooleanElasticsearchType(
        help_text="Whether or not the referenced network service was alive when checked.",
    )
    checked_at = DateElasticsearchType(
        help_text="The time at which the referenced network service was checked for liveness.",
    )
    liveness_cause = KeywordElasticsearchType(
        help_text="A string depicting how the liveness state in this model was determined.",
    )

    # Instantiation

    def __init__(
            self,
            is_alive=None,
            checked_at=None,
            liveness_cause=None,
            **kwargs
    ):
        super(NetworkServiceLivenessModel, self).__init__(**kwargs)
        self.is_alive = is_alive
        if checked_at is None:
            checked_at = DatetimeHelper.now()
        self.checked_at = checked_at
        self.liveness_cause = liveness_cause

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import RandomHelper, DatetimeHelper, WsFaker
        to_populate.is_alive = RandomHelper.flip_coin()
        to_populate.checked_at = DatetimeHelper.now()
        to_populate.liveness_cause = WsFaker.get_word()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
