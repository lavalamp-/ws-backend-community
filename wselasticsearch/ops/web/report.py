# -*- coding: utf-8 -*-
from __future__ import absolute_import

from wselasticsearch.query import WebServiceReportQuery


def get_latest_web_service_report_ids(org_uuid):
    """
    Get a list of strings containing all of the IDs associated with all of the latest web service reports
    associated with the given organization.
    :param org_uuid: The UUID of the organization.
    :return: A list of strings containing all of the IDs associated with all of the latest web service reports
    associated with the given organization.
    """
    query = WebServiceReportQuery(max_size=True, suppress_source=True)
    query.filter_by_latest_scan()
    response = query.search(org_uuid)
    return [x["_id"] for x in response.results]


def get_web_service_scan_uuid_from_report_id(org_uuid=None, report_id=None):
    """
    Get the web service scan UUID from the given web service report.
    :param org_uuid: The UUID of the organization to retrieve data for.
    :param report_id: The ID of the web service report document to retrieve.
    :return: The web service scan UUID for the given web service report.
    """
    query = WebServiceReportQuery(max_size=True)
    query.queried_fields = ["web_service_scan_uuid"]
    response = query.get(index=org_uuid, doc_id=report_id)
    return response.web_service_scan_uuid
