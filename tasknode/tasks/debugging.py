# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from ..app import websight_app
from .base import DatabaseTask

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=DatabaseTask)
def debugging_database_task(self, *args, **kwargs):
    """
    This is a task meant to be used for debugging purposes.
    :param args: Positional arguments.
    :param kwargs: Keyword arguments.
    :return: None
    """
    logger.warning("In debugging_database_task.")
    logger.warning("Args are: %s" % (args,))
    logger.warning("Kwargs are: %s" % (kwargs,))
    logger.warning("Self dir is: %s" % (dir(self),))
    logger.warning("Request is: %s" % (self.request,))
