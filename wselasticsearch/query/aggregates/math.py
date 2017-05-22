# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import TermsAggregate, BaseElasticsearchAggregate
from .exception import TooManyCountError


class CountAggregate(TermsAggregate):
    """
    A class for representing a terms aggregation that is used to count the instances of a field
    that match a value.
    """

    # Class Members

    # Instantiation

    def __init__(self, term_value=None, **kwargs):
        super(CountAggregate, self).__init__(**kwargs)
        if isinstance(term_value, int):
            self.term_value = [term_value]
        else:
            self.term_value = term_value

    # Static Methods

    # Class Methods

    @classmethod
    def unpack_response(cls, response):
        if len(response["buckets"]) == 1:
            return response["buckets"][0]["doc_count"]
        elif len(response["buckets"]) > 1:
            raise TooManyCountError(
                "Total of %s buckets returned when there should only have been one."
                % (len(response["buckets"]),)
            )
        else:
            return 0

    # Public Methods

    # Protected Methods

    def _get_aggregate_dict(self):
        to_return = super(CountAggregate, self)._get_aggregate_dict()
        to_return["terms"]["include"] = self.term_value
        return to_return

    # Private Methods

    # Properties

    # Representation and Comparison


class SumAggregate(BaseElasticsearchAggregate):
    """
    This is an Elasticsearch aggregate class used for calculating the sum of a field.
    """

    # Class Members

    # Instantiation

    def __init__(self, field=None, *args, **kwargs):
        super(SumAggregate, self).__init__(*args, **kwargs)
        self.field = field

    # Static Methods

    # Class Methods

    @classmethod
    def unpack_response(cls, response):
        return response["value"]

    # Public Methods

    # Protected Methods

    def _get_aggregate_dict(self):
        return {
            "sum": {
                "field": self.field
            }
        }

    # Private Methods

    # Properties

    # Representation and Comparison
