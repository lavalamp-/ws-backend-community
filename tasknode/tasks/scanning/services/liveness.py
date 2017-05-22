# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import chain
from celery.utils.log import get_task_logger
from datetime import datetime

from wselasticsearch.models import NetworkServiceLivenessModel
from ....app import websight_app
from ...base import ServiceTask
from .exception import UnknownProtocolError, UnsupportedProtocolError
from .ssl import inspect_tcp_service_for_ssl_support
from .fingerprinting import fingerprint_tcp_service
from lib.inspection import PortInspector
from lib import DatetimeHelper

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=ServiceTask)
def check_network_service_for_liveness(
        self,
        org_uuid=None,
        service_uuid=None,
        do_fingerprinting=True,
        do_ssl_inspection=True,
        scan_uuid=None,
):
    """
    Check the referenced network service to see if a connection can be made to it.
    :param org_uuid: The UUID of the organization to check the service on behalf of.
    :param service_uuid: The UUID of the network service to check for liveness.
    :param do_fingerprinting: Whether or not to continue with service fingerprinting.
    :param do_ssl_inspection: Whether or not to gather information about SSL if the service
    is alive and supports SSL.
    :param scan_uuid: The UUID of the network service scan that this liveness check is associated
    with.
    :return: None
    """
    ip_address, port, protocol = self.get_endpoint_information(service_uuid)
    logger.info(
        "Checking service at %s:%s (%s) for liveness for organization %s. Scan is %s."
        % (ip_address, port, protocol, org_uuid, scan_uuid)
    )
    if protocol == "tcp":
        check_sig = check_tcp_service_for_liveness.si(
            org_uuid=org_uuid,
            do_fingerprinting=do_fingerprinting,
            do_ssl_inspection=do_ssl_inspection,
            scan_uuid=scan_uuid,
            service_uuid=service_uuid,
        )
        self.finish_after(signature=check_sig)
    elif protocol == "udp":
        raise UnsupportedProtocolError(message="No support for protocol %s." % (protocol,))
    else:
        raise UnknownProtocolError(message="Protocol was %s." % (protocol,))


@websight_app.task(bind=True, base=ServiceTask)
def check_tcp_service_for_liveness(
        self,
        org_uuid=None,
        do_fingerprinting=True,
        do_ssl_inspection=True,
        scan_uuid=None,
        service_uuid=None,
):
    """
    Check to see if the given TCP network service is alive.
    :param org_uuid: The UUID of the organization to check the service on behalf of.
    :param do_fingerprinting: Whether or not to continue with service fingerprinting.
    :param do_ssl_inspection: Whether or not to gather information about SSL if the service
    is alive and supports SSL.
    :param scan_uuid: The UUID of the network service scan that this liveness check is associated
    with.
    :param service_uuid: The UUID of the network service to check for liveness.
    :return: None
    """
    ip_address, port, protocol = self.get_endpoint_information(service_uuid)
    logger.info(
        "Checking to see if TCP service at %s:%s is alive for organization %s. Scan is %s."
        % (ip_address, port, org_uuid, scan_uuid)
    )
    inspector = PortInspector(address=ip_address, port=port, protocol="tcp")
    service_alive = inspector.check_if_open()
    liveness_check = NetworkServiceLivenessModel.from_database_model_uuid(
        uuid=scan_uuid,
        db_session=self.db_session,
        is_alive=service_alive,
        checked_at=DatetimeHelper.now(),
    )
    liveness_check.save(org_uuid)
    logger.info(
        "TCP service at %s:%s %s alive. Updated Elasticsearch successfully."
        % (ip_address, port, "is" if service_alive else "is not")
    )
    next_tasks = []
    if not service_alive:
        logger.info(
            "TCP service at %s:%s was not alive. Not performing any additional inspection."
            % (ip_address, port)
        )
        return
    if do_ssl_inspection:
        next_tasks.append(inspect_tcp_service_for_ssl_support.si(
            org_uuid=org_uuid,
            network_service_uuid=service_uuid,
            network_service_scan_uuid=scan_uuid,
        ))
    if do_fingerprinting:
        next_tasks.append(fingerprint_tcp_service.si(
            org_uuid=org_uuid,
            service_uuid=service_uuid,
            scan_uuid=scan_uuid,
        ))
    if len(next_tasks) > 0:
        logger.info(
            "Kicking off %s tasks to continue investigation of TCP service at %s:%s for organization %s."
            % (len(next_tasks), ip_address, port, org_uuid)
        )
        canvas_sig = chain(next_tasks)
        self.finish_after(signature=canvas_sig)
    else:
        logger.info(
            "No further tasks to be performed after TCP liveness check at %s:%s for organization %s."
            % (ip_address, port, org_uuid)
        )
