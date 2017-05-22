# -*- coding: utf-8 -*-
from __future__ import absolute_import

from wselasticsearch.query import WebScanMultidocQuery


def update_web_service_scan_from_report(scan_uuid=None, web_service_report=None, org_uuid=None):
    """
    Update all of the documents currently indexed in Elasticsearch for the given web service scan to reflect
    the state of the given web service report.
    :param scan_uuid: The UUID of the web service scan to update.
    :param web_service_report: The WebServiceReportModel to update documents based off of.
    :param org_uuid: The UUID of the organization that owns the web service scan.
    :return: The Elasticsearch response.
    """
    query = WebScanMultidocQuery()
    query.filter_by_web_service_scan(scan_uuid)
    for update_field in web_service_report.update_fields:
        field_value = getattr(web_service_report, update_field)
        if field_value is not None:
            query.update_field(key=update_field, value=field_value)
    return query.update_by_query(org_uuid)


def update_web_service_scan_latest(scan_uuid=None, org_uuid=None):
    """
    Update the referenced web service scan and set it as the latest scan to have been run.
    :param scan_uuid: The UUID of the web service scan to update records for.
    :param org_uuid: The UUID of the organization that owns the web service scan.
    :return: The Elasticsearch response.
    """
    return update_web_service_scan_latest_state(scan_uuid=scan_uuid, latest_state=True, org_uuid=org_uuid)


def update_web_service_scan_latest_state(scan_uuid=None, latest_state=None, org_uuid=None):
    """
    Update all of the Elasticsearch documents associated with the given web service scan to reflect
    whether or not they are a part of the latest web service scan.
    :param scan_uuid: The UUID of the web service scan to update.
    :param latest_state: Whether or not the results of the referenced web service scan constitute the
    latest data retrieved from the service.
    :param org_uuid: The UUID of the organization that owns the web service.
    :return: The Elasticsearch response.
    """
    query = WebScanMultidocQuery()
    query.filter_by_web_service_scan(scan_uuid)
    query.update_field(key="is_latest_scan", value=latest_state)
    return query.update_by_query(org_uuid)


def update_web_service_scan_not_latest(scan_uuid=None, org_uuid=None):
    """
    Update the referenced web service scan and remove it as the latest scan to have been run.
    :param scan_uuid: The UUID of the web service scan to update records for.
    :param org_uuid: The UUID of the organization that owns the web service scan.
    :return: The Elasticsearch response.
    """
    return update_web_service_scan_latest_state(scan_uuid=scan_uuid, latest_state=False, org_uuid=org_uuid)


def update_web_service_scan_tech_report(scan_uuid=None, tech_report=None, org_uuid=None):
    """
    Update all of the documents currently indexed in Elasticsearch for the given web service scan to reflect
    the state of the technology report.
    :param scan_uuid: The UUID of the web service scan to update.
    :param tech_report: The web service technologies report object to update scan results with.
    :param org_uuid: The UUID of the organization that owns the web service scan.
    :return: The Elasticsearch response.
    """
    query = WebScanMultidocQuery()
    query.filter_by_web_service_scan(scan_uuid)
    for mapping_field in tech_report.mapping_fields:
        field_value = getattr(tech_report, mapping_field)
        if field_value is not None:
            query.update_field(key=mapping_field, value=field_value)
    return query.update_by_query(org_uuid)
