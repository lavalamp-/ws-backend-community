# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from lib import ConfigManager
from .base import PubSubTask
from ...app import websight_app

logger = get_task_logger(__name__)
config = ConfigManager.instance()


@websight_app.task(bind=True, base=PubSubTask)
def process_pubsub_queue(self):
    """
    Process the contents of the pubsub queue.
    :return: None
    """
    self.pubsub_manager.process_all_outstanding_messages(
        topic=config.pubsub_receive_topic,
    )
