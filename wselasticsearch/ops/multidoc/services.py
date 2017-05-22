# -*- coding: utf-8 -*-
from __future__ import absolute_import

from wselasticsearch.query import NetworkServiceScanMultidocQuery


def update_network_service_scan_latest_state(scan_uuid=None, latest_state=None, org_uuid=None):
    """
    Update all of the Elasticsearch documents associated with the given network service scan to
    have their is_latest_scan state set to latest_state.
    :param scan_uuid: The UUID of the network service scan to filter on.
    :param latest_state: The value to set is_latest_scan to.
    :param org_uuid: The UUID of the organization that owns the given network service scan.
    :return: The Elasticsearch response.
    """
    query = NetworkServiceScanMultidocQuery()
    query.filter_by_network_service_scan(scan_uuid)
    query.update_field(key="is_latest_scan", value=latest_state)
    return query.update_by_query(org_uuid)


def update_not_network_service_scan_latest_state(
        scan_uuid=None,
        latest_state=None,
        org_uuid=None,
        network_service_uuid=None,
):
    """
    Update all of the Elasticsearch documents associated with the given network service that are NOT
    associated with the given network service scan to have their is_latest_scan values updated to
    latest_state.
    :param scan_uuid: The UUID of the network service scan to filter on.
    :param latest_state: The value to set is_latest_scan to.
    :param org_uuid: The UUID of the organization that owns the network service scan.
    :param network_service_uuid: The UUID of the network service that was scanned.
    :return: None
    """
    query = NetworkServiceScanMultidocQuery()
    query.filter_by_not_network_service_scan(scan_uuid)
    query.filter_by_network_service(network_service_uuid)
    query.update_field(key="is_latest_scan", value=latest_state)
    return query.update_by_query(org_uuid)
