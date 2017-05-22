# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseDomainNameScanModel
from ..types import *


class DomainServiceLivenessModel(BaseDomainNameScanModel):
    """
    This is an Elasticsearch model for representing the results of a liveness check as performed
    as a part of a domain name scan.
    """

    # Class Members

    is_alive = BooleanElasticsearchType()
    checked_at = DateElasticsearchType()

    # Instantiation

    def __init__(self, is_alive=None, checked_at=None, **kwargs):
        super(DomainServiceLivenessModel, self).__init__(**kwargs)
        self.is_alive = is_alive
        self.checked_at = checked_at

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import RandomHelper, DatetimeHelper
        to_populate.is_alive = RandomHelper.flip_coin()
        to_populate.checked_at = DatetimeHelper.now()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
