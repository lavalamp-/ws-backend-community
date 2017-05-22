# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from lib.fingerprinting import HttpFingerprinter, HttpsFingerprinter
from .....app import websight_app
from ....base import ServiceTask

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=ServiceTask)
def check_service_for_http(self, org_uuid=None, scan_uuid=None, ip_address=None, port=None, service_uuid=None):
    """
    Check to see if the given remote service is running HTTP.
    :param org_uuid: The UUID of the organization to check the service on behalf of.
    :param scan_uuid: The UUID of the network service scan that this service fingerprinting is
    associated with.
    :param ip_address: The IP address where the service is running.
    :param port: The port where the service is running.
    :param service_uuid: The UUID of the network service to check for HTTP service.
    :return: None
    """
    logger.info(
        "Now checking to see if remote TCP service at %s:%s is running HTTP. Organization is %s, scan is %s."
        % (ip_address, port, org_uuid, scan_uuid)
    )
    fingerprinter = HttpFingerprinter(ip_address=ip_address, port=port)
    fingerprinter.perform_fingerprinting()
    logger.info(
        "TCP service at %s:%s found %s running HTTP."
        % (ip_address, port, "to be" if fingerprinter.fingerprint_found else "not to be")
    )
    result_record = fingerprinter.to_es_model(model_uuid=scan_uuid, db_session=self.db_session)
    result_record.save(org_uuid)
    logger.info(
        "Elasticsearch updated with HTTP fingerprint result for TCP endpoint %s:%s. Organization was %s, scan was %s."
        % (ip_address, port, org_uuid, scan_uuid)
    )


@websight_app.task(bind=True, base=ServiceTask)
def check_service_for_https(
        self,
        org_uuid=None,
        scan_uuid=None,
        ip_address=None,
        port=None,
        ssl_version=None,
        service_uuid=None,
):
    """
    Check to see if the given remote service is running HTTPS.
    :param org_uuid: The UUID of the organization to check the service on behalf of.
    :param scan_uuid: The UUID of the network service scan that this service fingerprinting is
    associated with.
    :param ip_address: The IP address where the service is running.
    :param port: The port where the service is running.
    :param ssl_version: The version of SSL to use to connect to the remote service.
    :param service_uuid: The UUID of the network service to check for HTTP service.
    :return: None
    """
    logger.info(
        "Now checking to see if remote TCP service at %s:%s is running HTTPS with SSL version %s. "
        "Organization is %s, scan is %s."
        % (ip_address, port, ssl_version, org_uuid, scan_uuid)
    )
    fingerprinter = HttpsFingerprinter(ip_address=ip_address, port=port, ssl_version=ssl_version)
    fingerprinter.perform_fingerprinting()
    logger.info(
        "TCP service at %s:%s found %s running HTTPS."
        % (ip_address, port, "to be" if fingerprinter.fingerprint_found else "not to be")
    )
    result_record = fingerprinter.to_es_model(model_uuid=scan_uuid, db_session=self.db_session)
    result_record.save(org_uuid)
    logger.info(
        "Elasticsearch updated with HTTPS fingerprint result for TCP endpoint %s:%s. Organization was %s, scan was %s."
        % (ip_address, port, org_uuid, scan_uuid)
    )
