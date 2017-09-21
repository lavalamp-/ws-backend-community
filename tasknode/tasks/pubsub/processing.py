# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from ..base import DatabaseTask
from ...app import websight_app

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=DatabaseTask)
def process_pubsub_queue(self):
    """
    Process the contents of the pubsub queue.
    :return: None
    """
    logger.error("HEYOOOOOO PROCESSING THAT PUBSUB QUEUE BABY YEAAAA")
