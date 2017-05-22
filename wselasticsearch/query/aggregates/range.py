# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchAggregate
from .exception import InvalidRangeError


class RangeAggregate(BaseElasticsearchAggregate):
    """
    This is an Elasticsearch aggregate class responsible for handling range aggregates.
    """

    # Class Members

    # Instantiation

    def __init__(self, field=None, *args, **kwargs):
        kwargs["include_size"] = False
        super(RangeAggregate, self).__init__(*args, **kwargs)
        self.field = field
        self._ranges = []

    # Static Methods

    # Class Methods

    @classmethod
    def unpack_response(cls, response):
        to_return = []
        if isinstance(response["buckets"], dict):
            for k, v in response["buckets"].iteritems():
                to_return.append({
                    "count": v["doc_count"],
                    "label": k,
                })
        else:
            for bucket in response["buckets"]:
                to_add = {
                    "count": bucket["doc_count"]
                }
                label = []
                if "from" in bucket:
                    label.append(bucket["from"])
                if "to" in bucket:
                    label.append(bucket["to"])
                to_add["label"] = "-".join(label)
                to_return.append(to_add)
        return to_return

    # Public Methods

    def add_range(self, range_from=None, range_to=None, key=None,):
        """
        Add the given range to the ranges held by this aggregate.
        :param range_from: Where the range should start.
        :param range_to: Where the range should end.
        :param key: The key to associate with the range.
        :return: None
        """
        self._ranges.append(ElasticsearchRange(range_from=range_from, range_to=range_to, key=key))

    def add_ranges(self, start=None, stop=None, step_count=None):
        """
        Add ranges to this aggregate that start at the given value, stop at the given value, and take
        the specified number of steps.
        :param start: The beginning of the range.
        :param stop: The end of the range.
        :param step_count: The number of buckets to cut the ranges into.
        :return: None
        """
        if step_count < 3:
            raise InvalidRangeError(
                "Cannot add ranges with a step count less than 3. Step count was %s."
                % (step_count,)
            )
        step_size = (start - stop) / (step_count - 2)
        self.add_range(range_to=start)
        for i in range(start, stop, step_size):
            self.add_range(range_from=i, range_to=i+step_size)
        self.add_range(range_from=stop)

    # Protected Methods

    def _get_aggregate_dict(self):
        to_return = super(RangeAggregate, self)._get_aggregate_dict()
        to_return["field"] = self.field
        to_return["ranges"] = [x.to_dict() for x in self.ranges]
        if self.is_keyed:
            to_return["keyed"] = True
        return {
            "range": to_return
        }

    # Private Methods

    # Properties

    @property
    def is_keyed(self):
        """
        Get whether or not the ranges contained within this object are keyed.
        :return: whether or not the ranges contained within this object are keyed.
        """
        return any([x.key is not None for x in self.ranges])

    @property
    def ranges(self):
        """
        Get the list of ranges that are currently contained within this range aggregate.
        :return: the list of ranges that are currently contained within this range aggregate.
        """
        return self._ranges

    # Representation and Comparison


class ElasticsearchRange(object):
    """
    This is a simple class for representing a range as found within an Elasticsearch range aggregate.
    """

    def __init__(self, range_from=None, range_to=None, key=None):
        self.range_from = range_from
        self.range_to = range_to
        self.key = key

    def to_dict(self):
        """
        Convert the current state of this range into a dictionary for using in an Elasticsearch range
        aggregate.
        :return: A dictionary for using in an Elasticsearch range aggregate.
        """
        to_return = {}
        if self.range_from is not None:
            to_return["from"] = self.range_from
        if self.range_to is not None:
            to_return["to"] = self.range_to
        if self.key is not None:
            to_return["key"] = self.key
        return to_return

