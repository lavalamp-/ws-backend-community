# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from lib import ConfigManager
from lib.sqlalchemy import get_org_ip_address_monitoring_status, update_org_ip_address_monitoring_state, \
    update_org_network_service_monitoring_state
from ...app import websight_app
from ..base import DatabaseTask
from .services import network_service_inspection_pass

logger = get_task_logger(__name__)
config = ConfigManager.instance()


@websight_app.task(bind=True, base=DatabaseTask)
def initialize_ip_address_monitoring(self, ip_uuid=None, org_uuid=None, scan_uuid=None):
    """
    Initialize monitoring for the given IP address and organization.
    :param ip_uuid: The UUID of the IP address to monitor.
    :param org_uuid: The UUID of the organization that owns the IP address.
    :param scan_uuid: The UUID of the Zmap scan where the IP address was discovered in.
    :return: None
    """
    logger.info(
        "Now initializing IP address monitoring for IP %s. Organization is %s, scan is %s."
        % (ip_uuid, org_uuid, scan_uuid)
    )
    self.db_session.execute("begin;")
    monitoring_status = get_org_ip_address_monitoring_status(
        ip_uuid=ip_uuid,
        db_session=self.db_session,
        with_for_update=True,
    )
    if monitoring_status:
        logger.info(
            "IP address %s for organization %s is already being monitored."
            % (ip_uuid, org_uuid)
        )
        return
    logger.info(
        "IP address %s for organization %s is not monitored. Starting monitoring now."
        % (ip_uuid, org_uuid)
    )
    monitor_ip_address.si(
        ip_uuid=ip_uuid,
        org_uuid=org_uuid,
        schedule_again=True,
    ).apply_async()
    update_org_ip_address_monitoring_state(
        ip_uuid=ip_uuid,
        state=True,
        db_session=self.db_session,
    )
    self.db_session.commit()
    self.db_session.execute("end;")


@websight_app.task(bind=True, base=DatabaseTask)
def initialize_network_service_monitoring(self, service_uuid=None, org_uuid=None, scan_uuid=None):
    """
    Initialize monitoring for the given network service and organization.
    :param service_uuid: The UUID of the network service to monitor.
    :param org_uuid: The UUID of the organization that owns the network service.
    :param scan_uuid: The UUID of the Zmap scan where the network service was discovered.
    :return: None
    """
    logger.info(
        "Now initializing network service monitoring for service %s. Organization is %s, scan is %s."
        % (service_uuid, org_uuid, scan_uuid)
    )
    # self.db_session.execute("begin;")
    # monitoring_status = get_org_network_service_monitoring_status(
    #     service_uuid=service_uuid,
    #     db_session=self.db_session,
    #     with_for_update=True,
    # )
    # if monitoring_status:
    #     logger.info(
    #         "Network service %s for organization %s is already being monitored."
    #         % (service_uuid, org_uuid)
    #     )
    #     self.db_session.execute("end;")
    #     return
    logger.info(
        "Network service %s for organization %s is not monitored. Starting monitoring now."
        % (service_uuid, org_uuid)
    )
    network_service_inspection_pass.si(
        service_uuid=service_uuid,
        org_uuid=org_uuid,
        schedule_again=True,
    ).apply_async()
    update_org_network_service_monitoring_state(
        service_uuid=service_uuid,
        state=True,
        db_session=self.db_session,
    )
    self.db_session.commit()
    # self.db_session.execute("end;")


@websight_app.task(bind=True, base=DatabaseTask)
def monitor_ip_address(self, ip_uuid=None, org_uuid=None, schedule_again=True):
    """
    Kick off all the necessary tasks for monitoring the given IP address and schedule another monitoring
    task.
    :param ip_uuid: The UUID of the OrganizationIpAddress to monitor.
    :param org_uuid: The UUID of the organization to monitor the IP address on behalf of.
    :param schedule_again: Whether or not to schedule another monitoring task.
    :return: None
    """
    logger.info(
        "Now starting monitoring pass for IP address %s. Organization is %s."
        % (ip_uuid, org_uuid)
    )
