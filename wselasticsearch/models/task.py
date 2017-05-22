# -*- coding: utf-8 -*-
from __future__ import absolute_import

from datetime import datetime

from .base import BaseElasticsearchModel
from .types import *


class TaskResultModel(BaseElasticsearchModel):
    """
    An Elasticsearch model for representing the results of a Task.
    """

    # Class Members

    name = KeywordElasticsearchType()
    start_time = DateElasticsearchType()
    end_time = DateElasticsearchType()
    duration = DoubleElasticsearchType()
    uuid = KeywordElasticsearchType()
    successful = BooleanElasticsearchType()
    traceback = TextElasticsearchType()

    # Instantiation

    def __init__(
            self,
            name=None,
            start_time=None,
            end_time=None,
            uuid=None,
            successful=None,
            traceback=None,
    ):
        self.name = name
        self.start_time = start_time
        self.end_time = end_time
        self.duration = (end_time - start_time).total_seconds()
        self.uuid = uuid
        self.successful = successful
        self.traceback = traceback

    # Static Methods

    @classmethod
    def create_dummy(cls):
        from lib import RandomHelper, WsFaker
        start_time = WsFaker.get_past_time(minutes=20)
        end_time = datetime.now()
        is_successful = RandomHelper.flip_coin()
        traceback = WsFaker.get_traceback(base64_encoded=True) if not is_successful else None
        return TaskResultModel(
            name=WsFaker.get_task_function_name(),
            start_time=start_time,
            end_time=end_time,
            uuid=WsFaker.create_uuid(),
            successful=is_successful,
            traceback=traceback,
        )

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s, %s, %s)>" \
               % (
                   self.__class__.__name__,
                   self.name,
                   "successful" if self.successful else "failed",
                   self.start_time,
                   self.end_time,
               )

