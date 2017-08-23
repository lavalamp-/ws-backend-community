# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group
from celery.utils.log import get_task_logger
import time

from lib.inspection import WebScanInspector
from wselasticsearch.ops import update_web_service_scan_from_report, get_latest_web_service_report_ids, \
    get_web_service_scan_uuid_from_report_id
from ......app import websight_app
from .....base import ServiceTask, WebServiceTask
from lib import ConfigManager

config = ConfigManager.instance()
logger = get_task_logger(__name__)


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def create_report_for_web_service_scan(
        self,
        org_uuid=None,
        web_service_scan_uuid=None,
        web_service_uuid=None,
        order_uuid=None,
):
    """
    Analyze the data collected during the given web service scan, create a WebServiceReportModel based on
    the collected data, update all of the Elasticsearch documents associated with the scan to reflect
    the collected data, and index the WebServiceReportModel.
    :param org_uuid: The UUID of the organization that owns the web service scan.
    :param web_service_scan_uuid: The UUID of the scan to generate the headers report from.
    :param web_service_uuid: The UUID of the web service that was scanned.
    :return: None
    """
    logger.info(
        "Now creating WebServiceReport for web service scan %s. Organization is %s."
        % (web_service_scan_uuid, org_uuid)
    )
    self.wait_for_es()
    inspector = WebScanInspector(web_scan_uuid=web_service_scan_uuid, db_session=self.db_session)
    report = inspector.to_es_model(model_uuid=web_service_scan_uuid, db_session=self.db_session)
    logger.info(
        "Sleeping for %s seconds to allow time for Elasticsearch to complete indexing..."
        % (config.celery_es_update_delay,)
    )
    self.wait_for_es()
    response = update_web_service_scan_from_report(scan_uuid=web_service_scan_uuid, web_service_report=report, org_uuid=org_uuid)
    logger.info(
        "A total of %s documents were updated. Now saving report."
        % (response.updated_count,)
    )
    report.save(org_uuid)
    logger.info(
        "Web service report saved successfully for web service scan %s, organization %s."
        % (web_service_scan_uuid, org_uuid)
    )


@websight_app.task(bind=True, base=ServiceTask)
def update_latest_web_service_reports_for_organization(self, org_uuid=None):
    """
    Update all of the web service reports for the given organization based on the current state of the web
    service inspector.
    :param org_uuid: The UUID of the organization to update web service reports for.
    :return: None
    """
    logger.info(
        "Now updating all web service reports for organization %s."
        % (org_uuid,)
    )
    report_ids = get_latest_web_service_report_ids(org_uuid)
    logger.info(
        "Total of %s web service reports found for organization %s."
        % (len(report_ids), org_uuid)
    )
    task_sigs = []
    for report_id in report_ids:
        task_sigs.append(update_web_service_report_for_organization.si(
            doc_id=report_id,
            org_uuid=org_uuid,
            is_latest=True,
        ))
    canvas_sig = group(task_sigs)
    logger.info(
        "Kicking off a total of %s tasks to update web service reports for organization %s."
        % (len(task_sigs), org_uuid)
    )
    self.finish_after(signature=canvas_sig)


@websight_app.task(bind=True, base=ServiceTask)
def update_web_service_report_for_organization(self, org_uuid=None, doc_id=None, is_latest=True):
    """
    Update the given web service report for the given organization based on the current state of the web service
    inspector.
    :param org_uuid: The UUID of the organization to update the web service report for.
    :param doc_id: The ID of the Elasticsearch document to update.
    :param is_latest: Whether or not the updated document should be set as the latest scan.
    :return: None
    """
    logger.info(
        "Now updating Elasticsearch web service report document %s for organization %s."
        % (doc_id, org_uuid)
    )
    scan_uuid = get_web_service_scan_uuid_from_report_id(org_uuid=org_uuid, report_id=doc_id)
    inspector = WebScanInspector(web_scan_uuid=scan_uuid, db_session=self.db_session)
    logger.info("Now collecting data and updating web service report.")
    inspector.update_document(
        doc_id=doc_id,
        model_uuid=scan_uuid,
        db_session=self.db_session,
        is_latest_scan=is_latest,
    )
    logger.info(
        "Web service report document %s has successfully been updated for organization %s."
        % (doc_id, org_uuid)
    )
