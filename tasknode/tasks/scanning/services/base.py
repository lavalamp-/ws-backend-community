# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import chain
from celery.utils.log import get_task_logger

from ....app import websight_app
from ...base import NetworkServiceTask, ScanTask
from lib import ConfigManager
from lib.sqlalchemy import get_network_service_scan_interval_for_organization, \
    update_network_service_scan_completed as update_network_service_scan_completed_op, \
    update_network_service_scanning_status as update_network_service_scanning_status_op, \
    check_network_service_scanning_status, create_new_network_service_scan
from .inspection import inspect_service_application
from .analysis import create_report_for_network_service_scan
from .fingerprinting import fingerprint_network_service
from wselasticsearch.ops import update_not_network_service_scan_latest_state, update_network_service_scan_latest_state
from wselasticsearch.models import NetworkServiceLivenessModel
from .ssl import inspect_tcp_service_for_ssl_support

logger = get_task_logger(__name__)
config = ConfigManager.instance()


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def scan_network_service(
        self,
        org_uuid=None,
        network_service_uuid=None,
        check_liveness=True,
        liveness_cause=None,
        order_uuid=None,
):
    """
    Scan the given network service for all network service relevant data supported by Web Sight.
    :param org_uuid: The UUID of the organization that owns the network service.
    :param network_service_uuid: The UUID of the network service to scan.
    :param check_liveness: Whether or not to check if the network service is alive.
    :param liveness_cause: The reason that this network service task was configured to not check
    for liveness.
    network service fingerprinting.
    :return: None
    """
    logger.info(
        "Now scanning network service %s for organization %s."
        % (network_service_uuid, org_uuid)
    )
    should_scan = check_network_service_scanning_status(
        db_session=self.db_session,
        service_uuid=network_service_uuid,
        update_status=True,
    )
    if not should_scan:
        logger.info(
            "Should not scan network service %s. Exiting."
            % (network_service_uuid,)
        )
    network_service_scan = create_new_network_service_scan(
        network_service_uuid=network_service_uuid,
        db_session=self.db_session,
    )
    self.db_session.add(network_service_scan)
    self.db_session.commit()
    scan_config = self.order.scan_config
    if check_liveness and scan_config.network_service_inspect_liveness:
        is_alive = self.inspector.check_if_open()
        if not is_alive:
            logger.info(
                "Network service at %s is not alive."
                % (network_service_uuid,)
            )
            return
        else:
            liveness_model = NetworkServiceLivenessModel.from_database_model(
                network_service_scan,
                is_alive=True,
                liveness_cause="network service scan liveness check"
            )
            liveness_model.save(org_uuid)
    else:
        liveness_model = NetworkServiceLivenessModel.from_database_model(
            network_service_scan,
            is_alive=True,
            liveness_cause=liveness_cause,
        )
        liveness_model.save(org_uuid)
    task_sigs = []
    task_kwargs = {
        "org_uuid": org_uuid,
        "network_service_uuid": network_service_uuid,
        "network_service_scan_uuid": network_service_scan.uuid,
        "order_uuid": order_uuid,
    }
    if scan_config.scan_ssl_support:
        supports_ssl = self.inspector.check_ssl_support()
        if supports_ssl:
            task_sigs.append(inspect_tcp_service_for_ssl_support.si(**task_kwargs))
    if scan_config.network_service_fingerprint:
        task_sigs.append(fingerprint_network_service.si(**task_kwargs))
    task_sigs.append(create_report_for_network_service_scan.si(**task_kwargs))
    task_sigs.append(update_network_service_scan_elasticsearch.si(**task_kwargs))
    task_sigs.append(update_network_service_scan_completed.si(**task_kwargs))
    scanning_status_sig = update_network_service_scanning_status.si(
        network_service_uuid=network_service_uuid,
        scanning_status=False,
        order_uuid=order_uuid,
    )
    task_sigs.append(scanning_status_sig)
    if scan_config.network_service_inspect_app:
        task_sigs.append(inspect_service_application.si(**task_kwargs))
    logger.info(
        "Now kicking off all necessary tasks to scan network service %s."
        % (network_service_uuid,)
    )
    canvas_sig = chain(task_sigs, link_error=scanning_status_sig)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def update_network_service_scan_elasticsearch(
        self,
        org_uuid=None,
        network_service_scan_uuid=None,
        network_service_uuid=None,
        order_uuid=None,
):
    """
    Update Elasticsearch so that all of the Elasticsearch documents associated with the given network
    service scan are marked as the latest results for the given network service, and all of the previously
    collected documents so that they are marked as not being related to the most recent scan.
    :param org_uuid: The UUID of the organization to update Elasticsearch on behalf of.
    :param network_service_scan_uuid: The UUID of the network service scan to update results for.
    :param network_service_uuid: The UUID of the network service that was analyzed.
    :return: None
    """
    logger.info(
        "Now updating Elasticsearch for network service scan %s. Organization is %s."
        % (network_service_scan_uuid, org_uuid)
    )
    self.wait_for_es()
    update_network_service_scan_latest_state(scan_uuid=network_service_scan_uuid, org_uuid=org_uuid, latest_state=True)
    update_not_network_service_scan_latest_state(
        scan_uuid=network_service_scan_uuid,
        org_uuid=org_uuid,
        latest_state=False,
        network_service_uuid=network_service_uuid,
    )
    logger.info(
        "Elasticsearch updated to reflect that network service scan %s is the latest network service scan "
        "for network service %s and organization %s."
        % (network_service_scan_uuid, network_service_uuid, org_uuid)
    )


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def update_network_service_scan_completed(
        self,
        network_service_scan_uuid=None,
        org_uuid=None,
        network_service_uuid=None,
        order_uuid=None,
):
    """
    Update the referenced NetworkServiceScan to show that the network service scan has completed.
    :param network_service_scan_uuid: The UUID of the NetworkServiceScan to update.
    :param org_uuid: The UUID of the organization that the scan was run on behalf of.
    :param network_service_uuid: The UUID of the network service that scanning was completed for.
    :return: None
    """
    logger.info(
        "Now updating NetworkServiceScan %s to show its completed. Organization is %s. Service is %s."
        % (network_service_scan_uuid, org_uuid, network_service_uuid)
    )
    update_network_service_scan_completed_op(scan_uuid=network_service_scan_uuid, db_session=self.db_session)
    self.commit_session()
    logger.info(
        "Successfully updated NetworkServiceScan %s as completed."
        % (network_service_scan_uuid,)
    )


#USED
@websight_app.task(bind=True, base=ScanTask)
def update_network_service_scanning_status(
        self,
        network_service_uuid=None,
        scanning_status=None,
        order_uuid=None,
):
    """
    Update the current scanning status of the given network service to the given value.
    :param network_service_uuid: The UUID of the network service to update.
    :param scanning_status: The status to set the scanning status to.
    :return: None
    """
    logger.info(
        "Now updating scanning status for network service %s to %s."
        % (network_service_uuid, scanning_status)
    )
    update_network_service_scanning_status_op(
        status=scanning_status,
        service_uuid=network_service_uuid,
        db_session=self.db_session,
    )
    self.db_session.commit()
    logger.info(
        "Scanning status for network service %s successfully updated to %s."
        % (network_service_uuid, scanning_status)
    )
