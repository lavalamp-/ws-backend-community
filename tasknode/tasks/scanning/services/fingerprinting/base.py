# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group, chain
from celery.utils.log import get_task_logger

from wselasticsearch.ops import get_supported_ssl_version_for_service
from .....app import websight_app
from ....base import ServiceTask, NetworkServiceTask
from .http import check_service_for_http, check_service_for_https
from ..inspection import inspect_tcp_service_application

logger = get_task_logger(__name__)


def get_tcp_service_fingerprinting_tasks():
    """
    Get a list of TCP service fingerprinting tasks.
    :return: A list of TCP service fingerprinting tasks.
    """
    return [
        check_service_for_http,
    ]


def get_tcp_ssl_service_fingerprinting_tasks():
    """
    Get a list of TCP SSL service fingerprinting tasks.
    :return: A list of TCP SSL service fingerprinting tasks.
    """
    return [
        check_service_for_https,
    ]


@websight_app.task(bind=True, base=NetworkServiceTask)
def fingerprint_network_service(self, org_uuid=None, network_service_uuid=None, network_service_scan_uuid=None):
    """
    Perform fingerprinting of the given network service.
    :param org_uuid: The UUID of the organization that owns the network service.
    :param network_service_uuid: The UUID of the network service to scan.
    :param network_service_scan_uuid: The UUID of the network service scan that these fingerprinting activities
    are a part of.
    :return: None
    """
    logger.info(
        "Now fingerprinting network service %s."
        % (network_service_uuid,)
    )
    if self.is_tcp_service:
        task_sig = fingerprint_tcp_service.si(
            org_uuid=org_uuid,
            service_uuid=network_service_uuid,
            scan_uuid=network_service_scan_uuid,
        )
        self.finish_after(signature=task_sig)
    elif self.is_udp_service:
        logger.warning(
            "No fingerprinting support for UDP network services at this time."
        )
        return


@websight_app.task(bind=True, base=ServiceTask)
def fingerprint_tcp_service(
        self,
        org_uuid=None,
        service_uuid=None,
        scan_uuid=None,
):
    """
    Perform fingerprinting of the given TCP network service.
    :param org_uuid: The UUID of the organization to check the service on behalf of.
    :param service_uuid: The UUID of the network service to fingerprint.
    if the network service is found to be alive.
    :param scan_uuid: The UUID of the network service scan that this service fingerprinting is associated
    with.
    :return: None
    """
    ip_address, port, protocol = self.get_endpoint_information(service_uuid)
    logger.debug(
        "Now performing TCP network service inspection for %s:%s for organization %s. Scan is %s."
        % (ip_address, port, org_uuid, scan_uuid)
    )
    task_sigs = []
    fingerprinting_sigs = []
    for fingerprinting_task in get_tcp_service_fingerprinting_tasks():
        fingerprinting_sigs.append(fingerprinting_task.si(
            org_uuid=org_uuid,
            ip_address=ip_address,
            port=port,
            scan_uuid=scan_uuid,
            service_uuid=service_uuid,
        ))
    supported_ssl_version = get_supported_ssl_version_for_service(
        org_uuid=org_uuid,
        scan_uuid=scan_uuid,
    )
    if supported_ssl_version is not None:
        for fingerprinting_task in get_tcp_ssl_service_fingerprinting_tasks():
            fingerprinting_sigs.append(fingerprinting_task.si(
                org_uuid=org_uuid,
                ip_address=ip_address,
                port=port,
                scan_uuid=scan_uuid,
                ssl_version=supported_ssl_version,
                service_uuid=service_uuid,
            ))
    task_sigs.append(group(fingerprinting_sigs))
    canvas_sig = chain(task_sigs)
    logger.debug(
        "Now kicking off a total of %s tasks to fingerprint TCP service at %s:%s for organization %s."
        % (len(fingerprinting_sigs), ip_address, port, org_uuid)
    )
    self.finish_after(signature=canvas_sig)
