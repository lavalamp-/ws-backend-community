# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from ...app import websight_app
from ..base import DatabaseTask
from .zmap import zmap_scan_organization
from lib import DatetimeHelper
from lib.sqlalchemy import get_network_scan_interval_for_organization

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=DatabaseTask)
def initiate_network_scans_for_organization(self, org_uuid=None, requeue=True):
    """
    Kick off network scans for the given organization and queue up an additional network
    scanning task for the next interval.
    :param org_uuid: The UUID of the organization to scan.
    :param requeue: Whether or not to queue up another network scanning task for the
    configured interval.
    :return: None
    """
    logger.info(
        "Kicking off all network scans for Organization %s."
        % (org_uuid,)
    )
    zmap_scan_organization.si(org_uuid=org_uuid).apply_async()
    if requeue:
        scan_interval = get_network_scan_interval_for_organization(
            org_uuid=org_uuid,
            db_session=self.db_session,
        )
        next_time = DatetimeHelper.seconds_from_now(scan_interval)
        logger.info(
            "Queueing up an additional instance of %s in %s seconds (%s)."
            % (self.name, scan_interval, next_time)
        )
        initiate_network_scans_for_organization.si(org_uuid=org_uuid, requeue=requeue).apply_async(eta=next_time)
    else:
        logger.info("Requeueing not enabled, therefore not queueing up another network scanning task.")

