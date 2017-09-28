# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from ..base import DatabaseTask
from ...app import websight_app

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=DatabaseTask)
def handle_scanning_order_from_pubsub(self, org_uuid=None, targets=None):
    """
    Create and kick off an order based on the contents of the UUID of the given organization
    and the list of targets to scan.
    :param org_uuid: The UUID of the organization to create the scan for.
    :param targets: A list of the targets to perform the scan on.
    :return: None
    """
    logger.error(
        "HERE WE ARE CHIPPY CHAP: %s, %s"
        % (org_uuid, targets)
    )
