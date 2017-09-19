# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group
from celery.utils.log import get_task_logger
import requests

from tasknode.app import websight_app
from tasknode.tasks.base import ScanTask
from lib.sqlalchemy import count_domains_for_order, \
    count_networks_for_order, get_network_scan_interval_for_organization, get_org_uuid_from_order, \
    get_monitored_domain_uuids_from_order
from lib import DatetimeHelper
from .dns import scan_domain_name
from .network import zmap_scan_order
from ..smtp import email_order_user_for_order_completion, email_org_users_for_order_completion

logger = get_task_logger(__name__)


#USED
@websight_app.task(bind=True, base=ScanTask)
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
    scan_config = self.scan_config
    if scan_config.scan_domain_names:
        domain_count = count_domains_for_order(db_session=self.db_session, order_uuid=order_uuid)
        logger.info(
            "Domain count for order %s is %s."
            % (order_uuid, domain_count)
        )
        if domain_count > 0:
            task_sigs.append(initiate_domain_scans_for_order.si(order_uuid=order_uuid, scan_endpoints=True))
    if scan_config.scan_network_ranges:
        network_count = count_networks_for_order(db_session=self.db_session, order_uuid=order_uuid)
        logger.info(
            "Networks count for order %s is %s."
            % (order_uuid, network_count)
        )
        if network_count > 0:
            task_sigs.append(initiate_network_scans_for_order.si(order_uuid=order_uuid, requeue=False))
    if len(task_sigs) > 0:
        task_sigs.append(handle_order_completion.si(order_uuid=order_uuid))
        canvas_sig = group(task_sigs)
        canvas_sig.apply_async()
        logger.info(
            "All scanning tasks for order %s kicked off successfully."
            % (order_uuid,)
        )
    else:
        logger.warning("No tasks were created as a result of call to handle_placed_order.")


#USED
@websight_app.task(bind=True, base=ScanTask)
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
            order_uuid=order_uuid,
        ))
    logger.info(
        "Now kicking off %s tasks as a group to scan domains for organization %s."
        % (len(task_sigs), org_uuid)
    )
    canvas_sig = group(task_sigs)
    canvas_sig.apply_async()


#USED
@websight_app.task(bind=True, base=ScanTask)
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
        initiate_network_scans_for_order.si(order_uuid=order_uuid, requeue=requeue).apply_async(eta=next_time)
    else:
        logger.info("Requeueing not enabled, therefore not queueing up another network scanning task.")


#USED
@websight_app.task(bind=True, base=ScanTask, max_retries=None)
def handle_order_completion(self, order_uuid=None, retry_interval=10, completion_count=1):
    """
    Check to see if the order associated with the given UUID has completed and, if it has, handle the completion
    of the order.
    :param order_uuid: The UUID of the order to check on.
    :param retry_interval: The time (in seconds) between checking on whether or not the referenced
    order has completed.
    :param completion_count: The number of outstanding tasks associated with an order that should indicate
    that the order has finished.
    :return: None
    """
    logger.info(
        "Now checking to see if order %s has completed."
        % (order_uuid,)
    )
    order_uuid_value = int(self.redis_helper.get(order_uuid))
    if order_uuid_value == completion_count:
        logger.info(
            "Order %s has completed!"
            % (order_uuid,)
        )
        scan_config = self.scan_config
        task_sigs = []
        if scan_config.completion_email_org_users:
            org = self.order.organization
            task_sigs.append(email_org_users_for_order_completion.si(
                order_uuid=order_uuid,
                org_uuid=org.uuid,
                org_name=org.name,
            ))
        elif scan_config.completion_email_order_user:
            org = self.order.organization
            task_sigs.append(email_order_user_for_order_completion.si(
                order_uuid=order_uuid,
                org_uuid=org.uuid,
                org_name=org.name,
            ))
        if scan_config.completion_web_hook_url:
            task_sigs.append(request_web_hook_for_order_completion.si(order_uuid=order_uuid))
        if len(task_sigs) > 0:
            canvas_sig = group(task_sigs)
            logger.info(
                "Now kicking off %s tasks to handle the completion of order %s."
                % (len(task_sigs), order_uuid)
            )
            self.finish_after(signature=canvas_sig)
        else:
            logger.info(
                "No tasks to run in response to completion of order %s."
                % (order_uuid,)
            )
    else:
        logger.info(
            "Order %s has not completed yet (%s tasks currently outstanding)."
            % (order_uuid, order_uuid_value,)
        )
        raise self.retry(countdown=retry_interval)


#USED
@websight_app.task(bind=True, base=ScanTask)
def request_web_hook_for_order_completion(self, order_uuid=None):
    """
    Submit an HTTP GET request to the web hook URL associated with the given order to indicate that the
    order has finished.
    :param order_uuid: The UUID of the order that finished.
    :return: None
    """
    scan_config = self.scan_config
    web_hook_url = scan_config.completion_web_hook_url
    if "?" in web_hook_url:
        web_hook_url = web_hook_url[:web_hook_url.find("?")]
    request_url = "%s?%s" % (web_hook_url, order_uuid)
    logger.info(
        "Now requesting URL %s to indicate that order %s has finished."
        % (request_url, order_uuid)
    )
    requests.get(request_url)
    logger.info(
        "Successfully requested URL %s."
        % (request_url,)
    )
