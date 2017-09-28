# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import PubSubManager
from ..base import DatabaseTask


class PubSubTask(DatabaseTask):
    """
    A base Celery task class for tasks that consume data out of PubSubs.
    """

    abstract = True

    @property
    def pubsub_manager(self):
        """
        Get the PubSub manager to use to communicate with the configured PubSub.
        :return: the PubSub manager to use to communicate with the configured PubSub.
        """
        return PubSubManager.instance()
