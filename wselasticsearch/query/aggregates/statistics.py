# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchAggregate


class HistogramAggregate(BaseElasticsearchAggregate):
    """
    A class for representing a histogram aggregation placed on an Elasticsearch query.
    """

    # Class Members

    # Instantiation

    def __init__(self, field=None, interval=None, *args, **kwargs):
        kwargs["include_size"] = False
        super(HistogramAggregate, self).__init__(*args, **kwargs)
        self.field = field
        self.interval = interval

    # Static Methods

    # Class Methods

    @classmethod
    def unpack_response(cls, response):
        to_return = []
        for bucket in response["buckets"]:
            to_return.append({
                "label": bucket["key"],
                "count": bucket["doc_count"],
            })
        return to_return

    # Public Methods

    # Protected Methods

    def _get_aggregate_dict(self):
        to_return = super(HistogramAggregate, self)._get_aggregate_dict()
        to_return["field"] = self.field
        to_return["interval"] = self.interval
        return {
            "histogram": to_return
        }

    # Private Methods

    # Properties

    # Representation and Comparison
