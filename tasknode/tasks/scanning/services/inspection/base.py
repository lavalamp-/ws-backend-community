# -*- coding: utf-8 -*-
from __future__ import absolute_import

import time

from celery import chain
from celery import group
from celery.utils.log import get_task_logger

from lib.sqlalchemy import get_protocol_from_network_service
from .web import inspect_https_service, inspect_http_service
from wselasticsearch.ops import get_successful_fingerprints_for_service
from ....base import ServiceTask
from .....app import websight_app
from lib import ConfigManager
from ..exception import UnsupportedProtocolError

config = ConfigManager.instance()
logger = get_task_logger(__name__)


def get_tcp_inspection_task_map():
    """
    Get a dictionary that maps fingerprinted service types to the tasks that perform
    application-level inspection.
    :return: A dictionary that maps fingerprinted service types to the tasks that perform
    application-level inspection.
    """
    return {
        "http": inspect_http_service,
        "https": inspect_https_service,
    }


@websight_app.task(bind=True, base=ServiceTask)
def inspect_service_application(self, org_uuid=None, network_service_scan_uuid=None, network_service_uuid=None):
    """
    Inspect the applications residing on the remote service.
    :param org_uuid: The UUID of the organization to inspect the service on behalf of.
    :param network_service_scan_uuid: The UUID of the NetworkScan that invoked this task.
    :param network_service_uuid: The UUID of the NetworkService to inspect.
    :return: None
    """
    logger.info(
        "Inspecting service %s for organization %s. Network scan was %s."
        % (network_service_uuid, org_uuid, network_service_scan_uuid)
    )
    protocol = get_protocol_from_network_service(network_service_uuid=network_service_uuid, db_session=self.db_session)
    task_signatures = []
    if protocol == "tcp":
        task_signatures.append(inspect_tcp_service_application.si(
            org_uuid=org_uuid,
            scan_uuid=network_service_scan_uuid,
            service_uuid=network_service_uuid,
        ))
    else:
        raise UnsupportedProtocolError("No support for service inspection with protocol %s." % (protocol,))
    canvas_sig = chain(task_signatures)
    canvas_sig.apply_async()


@websight_app.task(bind=True, base=ServiceTask)
def inspect_tcp_service_application(
        self,
        org_uuid=None,
        scan_uuid=None,
        service_uuid=None,
):
    """
    Inspect the application residing at the given TCP endpoint, if application-level inspection is
    currently supported.
    :param org_uuid: The UUID of the organization to check the service on behalf of.
    :param scan_uuid: The UUID of the network service scan that this service fingerprinting is associated
    with.
    :param service_uuid: The UUID of the network service to inspect.
    :return: None
    """
    ip_address, port, protocol = self.get_endpoint_information(service_uuid)
    logger.info(
        "Now starting inspection of TCP service at %s:%s. Organization is %s, scan is %s."
        % (ip_address, port, org_uuid, scan_uuid)
    )
    logger.info(
        "Waiting for %s seconds to allow Elasticsearch to finish indexing fingerprint results."
        % (config.celery_es_update_delay,)
    )
    time.sleep(config.celery_es_update_delay)
    service_names = get_successful_fingerprints_for_service(
        service_uuid=service_uuid,
        org_uuid=org_uuid,
        scan_uuid=scan_uuid,
    )
    if len(service_names) == 0:
        logger.info(
            "No services successfully fingerprinted for TCP endpoint at %s:%s."
            % (ip_address, port)
        )
        return
    task_map = get_tcp_inspection_task_map()
    if "http" in service_names and "https" in service_names:
        service_names.remove("http")
    task_signatures = []
    for service_name in service_names:
        if service_name in task_map:
            task_signatures.append(task_map[service_name].si(
                org_uuid=org_uuid,
                network_service_scan_uuid=scan_uuid,
                network_service_uuid=service_uuid,
            ))
    if len(task_signatures) == 0:
        logger.info(
            "None of the fingerprinted services for TCP endpoint %s:%s are supported."
            % (ip_address, port)
        )
        return
    canvas_sig = group(task_signatures)
    canvas_sig.apply_async()
