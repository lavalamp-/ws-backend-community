# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group
from celery.utils.log import get_task_logger

from ...base import ServiceTask, NetworkServiceTask
from ....app import websight_app
from wselasticsearch.ops import does_network_service_scan_support_ssl, get_latest_ssl_support_report_ids, \
    get_network_service_scan_uuid_from_ssl_report_id
from lib.inspection import SslSupportInspector

logger = get_task_logger(__name__)


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def create_report_for_network_service_scan(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Create a network service report reflecting the data gathered during the given network service scan.
    :param org_uuid: The UUID of the organization that owns the network service.
    :param network_service_uuid: The UUID of the network service that was scanned.
    :param network_service_scan_uuid: The UUID of the network service scan that this task is a part of.
    :return: None
    """
    logger.info(
        "Now creating a report for network service scan %s."
        % (network_service_scan_uuid,)
    )


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def create_ssl_support_report_for_network_service_scan(
        self,
        org_uuid=None,
        network_service_uuid=None,
        network_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Create an SslSupportReportModel based on the results of information gathered during the given
    network service scan.
    :param org_uuid: The UUID of the organization to analyze the results on behalf of.
    :param network_service_uuid: The UUID of the network service that was scanned.
    :param network_service_scan_uuid: The UUID of the network service scan to analyze.
    :return: None
    """
    logger.info(
        "Now analyzing results of network service scan %s to determine SSL support. Organization is %s."
        % (network_service_scan_uuid, org_uuid)
    )
    self.wait_for_es()
    inspector = SslSupportInspector(network_service_scan_uuid=network_service_scan_uuid, db_session=self.db_session)
    report = inspector.to_es_model(model_uuid=network_service_scan_uuid, db_session=self.db_session)
    report.save(org_uuid)
    logger.info(
        "Successfully generated SSL support report for network service scan %s."
        % (network_service_scan_uuid,)
    )


@websight_app.task(bind=True, base=ServiceTask)
def update_latest_ssl_support_reports_for_organization(self, org_uuid=None):
    """
    Update all of the ssl support reports for the given organization based on the current state of the SSL support
    inspector.
    :param org_uuid: The UUID of the organization to update SSL support reports for.
    :return: None
    """
    logger.info(
        "Now updating all of the latest SSL support reports for organization %s."
        % (org_uuid,)
    )
    report_ids = get_latest_ssl_support_report_ids(org_uuid)
    logger.info(
        "Total of %s SSL support reports found for organization %s."
        % (len(report_ids), org_uuid)
    )
    task_sigs = []
    for report_id in report_ids:
        task_sigs.append(update_latest_ssl_support_report_for_organization.si(
            doc_id=report_id,
            org_uuid=org_uuid,
            is_latest=True,
        ))
    canvas_sig = group(task_sigs)
    logger.info(
        "Now kicking off %s tasks to update SSL support reports for organization %s."
        % (len(task_sigs), org_uuid)
    )
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=ServiceTask)
def update_latest_ssl_support_report_for_organization(self, org_uuid=None, doc_id=None, is_latest=True):
    """
    Update the given ssl support report for the given organization based on the current state of the SSL support
    inspector.
    :param org_uuid: The UUID of the organization to update the SSL support report for.
    :param doc_id: The ID of the Elasticsearch document to update.
    :param is_latest: Whether or not the updated document should be set as the latest scan.
    :return: None
    """
    logger.info(
        "Now updating Elasticsearch ssl support report document %s for organization %s."
        % (doc_id, org_uuid)
    )
    scan_uuid = get_network_service_scan_uuid_from_ssl_report_id(org_uuid=org_uuid, report_id=doc_id)
    inspector = SslSupportInspector(network_service_scan_uuid=scan_uuid, db_session=self.db_session)
    logger.info("Now collecting data and updating SSL support report.")
    inspector.update_document(
        doc_id=doc_id,
        model_uuid=scan_uuid,
        db_session=self.db_session,
        is_latest_scan=is_latest,
    )
    logger.info(
        "SSL support report document %s has successfully been updated for organization %s."
        % (doc_id, org_uuid)
    )
