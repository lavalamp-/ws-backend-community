# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import chain, group
from celery.utils.log import get_task_logger

from ...app import websight_app
from ..base import DatabaseTask
from .networks import initiate_network_scans_for_organization
from lib.sqlalchemy import count_included_domains_for_organization, count_included_networks_for_organization
from .dns import initiate_dns_scans_for_organization

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=DatabaseTask)
def initialize_scan_for_organization(self, org_uuid=None):
    """
    Kick off all of the necessary tasks for scanning the given organization.
    :param org_uuid: The UUID of the Organization to kick off scanning activities for.
    :return: None
    """
    logger.info(
        "Now kicking off all scans for organization %s."
        % (org_uuid,)
    )
    task_sigs = []
    included_domain_count = count_included_domains_for_organization(
        org_uuid=org_uuid,
        db_session=self.db_session,
    )
    if included_domain_count > 0:
        task_sigs.append(initiate_dns_scans_for_organization.si(
            org_uuid=org_uuid,
            scan_endpoints=True,
        ))
    included_network_count = count_included_networks_for_organization(
        org_uuid=org_uuid,
        db_session=self.db_session,
    )
    if included_network_count > 0:
        task_sigs.append(initiate_network_scans_for_organization.si(
            org_uuid=org_uuid,
            requeue=False,
        ))
    canvas_sig = group(task_sigs)
    canvas_sig.apply_async()
    logger.info(
        "All scanning tasks kicked off for organization %s."
        % (org_uuid,)
    )
