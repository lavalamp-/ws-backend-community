# -*- coding: utf-8 -*-
from __future__ import absolute_import

from datetime import timedelta

from lib import ConfigManager

config = ConfigManager.instance()


def get_periodic_tasks():
    """
    Get a dictionary to set the beat_schedule to based on the current Web Sight
    configuration.
    :return: A dictionary to set the beat_schedule to based on the current Web Sight
    configuration.
    """
    to_return = {}
    if config.pubsub_enabled:
        to_return["process-pubsub-queue"] = {
            "task": "tasknode.tasks.pubsub.processing.process_pubsub_queue",
            "schedule": timedelta(seconds=config.pubsub_poll_interval),
            "options": {
                "queue": config.celery_priority_queue_name,
            }
        }
    return to_return
