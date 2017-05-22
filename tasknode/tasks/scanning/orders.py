# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group
from celery.utils.log import get_task_logger

from tasknode.app import websight_app
from tasknode.tasks.base import DatabaseTask
from lib.sqlalchemy import count_domains_for_order, \
    count_networks_for_order, get_network_scan_interval_for_organization, get_org_uuid_from_order, \
    get_monitored_domain_uuids_from_order
from lib import DatetimeHelper
from .dns import initiate_dns_scan_for_organization, scan_domain_name
from .zmap import zmap_scan_order

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=DatabaseTask)
def handle_placed_order(self, order_uuid=None):
    """
    Handle the placement of the given order.
    :param order_uuid: The UUID of the order that was placed.
    :return: None
    """
    logger.info(
        "Now handling the placement of order %s."
        % (order_uuid,)
    )
    task_sigs = []
    domain_count = count_domains_for_order(db_session=self.db_session, order_uuid=order_uuid)
    logger.info(
        "Domain count for order %s is %s."
        % (order_uuid, domain_count)
    )
    if domain_count > 0:
        task_sigs.append(initiate_domain_scans_for_order.si(order_uuid=order_uuid, scan_endpoints=True))
    network_count = count_networks_for_order(db_session=self.db_session, order_uuid=order_uuid)
    logger.info(
        "Networks count for order %s is %s."
        % (order_uuid, network_count)
    )
    if network_count > 0:
        task_sigs.append(initiate_network_scans_for_order.si(order_uuid=order_uuid, requeue=False))
    canvas_sig = group(task_sigs)
    canvas_sig.apply_async()
    logger.info(
        "All scanning tasks for order %s kicked off successfully."
        % (order_uuid,)
    )


@websight_app.task(bind=True, base=DatabaseTask)
def initiate_domain_scans_for_order(self, order_uuid=None, scan_endpoints=True):
    """
    Initiate all of the domain name scans for the given order.
    :param order_uuid: The UUID of the order to initiate scans for.
    :param scan_endpoints: Whether or not to scan discovered endpoints for network services.
    :return: None
    """
    logger.info(
        "Now initiating all domain name scans for order %s. Scan endpoints is %s."
        % (order_uuid, scan_endpoints)
    )
    domain_uuids = get_monitored_domain_uuids_from_order(db_session=self.db_session, order_uuid=order_uuid)
    logger.info(
        "There are a total of %s domains associated with order %s."
        % (len(domain_uuids), order_uuid)
    )
    task_sigs = []
    org_uuid = get_org_uuid_from_order(order_uuid=order_uuid, db_session=self.db_session)
    for domain_uuid in domain_uuids:
        task_sigs.append(scan_domain_name.si(
            org_uuid=org_uuid,
            domain_uuid=domain_uuid,
        ))
    logger.info(
        "Now kicking off %s tasks as a group to scan domains for organization %s."
        % (len(task_sigs), org_uuid)
    )
    canvas_sig = group(task_sigs)
    canvas_sig.apply_async()


@websight_app.task(bind=True, base=DatabaseTask)
def initiate_network_scans_for_order(self, order_uuid=None, requeue=False):
    """
    Initiate all of the network scans for the given order.
    :param order_uuid: The UUID of the order to initiate network scans for.
    :param requeue: Whether or not to requeue the network scans.
    :return: None
    """
    logger.info(
        "Now initiating all network scans for order %s. Requeue is %s."
        % (order_uuid, requeue)
    )
    zmap_scan_order.si(order_uuid=order_uuid).apply_async()
    if requeue:
        org_uuid = get_org_uuid_from_order(order_uuid=order_uuid, db_session=self.db_session)
        scan_interval = get_network_scan_interval_for_organization(
            org_uuid=org_uuid,
            db_session=self.db_session,
        )
        next_time = DatetimeHelper.seconds_from_now(scan_interval)
        logger.info(
            "Queueing up an additional instance of %s in %s seconds (%s)."
            % (self.name, scan_interval, next_time)
        )
        initiate_network_scans_for_order.si(org_uuid=org_uuid, requeue=requeue).apply_async(eta=next_time)
    else:
        logger.info("Requeueing not enabled, therefore not queueing up another network scanning task.")


