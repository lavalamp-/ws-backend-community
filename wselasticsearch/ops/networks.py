# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..query import IpPortScanQuery, IpAddressScanMultidocQuery


#TESTME
def get_open_ports_from_ip_address_scan(ip_address_scan_uuid=None, org_uuid=None):
    """
    Get a list of tuples containing (1) the port number and (2) the protocol for all of the network
    services that were found to be open during the given IP address scan.
    :param ip_address_scan_uuid: The UUID of the IP address scan to filter results by.
    :param org_uuid: The UUID of the organization to query.
    :return: A list of tuples containing (1) the port number and (2) the protocol for all of the network
    services that were found to be open during the given IP address scan.
    """
    query = IpPortScanQuery(max_size=True)
    query.filter_by_ip_address_scan(ip_address_scan_uuid)
    response = query.search(org_uuid)
    to_return = set()
    for result in response.results:
        for port_result in result["_source"]["port_results"]:
            if port_result["port_status"] == "open":
                to_return.add((port_result["port_number"], port_result["port_protocol"]))
    return list(to_return)


#TESTME
def update_ip_address_scan_latest_state(scan_uuid=None, latest_state=None, org_uuid=None):
    """
    Update all of the Elasticsearch documents associated with the given IP address scan to
    have their is_latest_scan state set to latest_state.
    :param scan_uuid: The UUID of the IP address scan to update.
    :param latest_state: The status to set for is_latest_scan.
    :param org_uuid: The UUID of the organization to query.
    :return: The Elasticsearch response.
    """
    query = IpAddressScanMultidocQuery()
    query.filter_by_ip_address_scan(scan_uuid)
    query.update_field(key="is_latest_scan", value=latest_state)
    return query.update_by_query(org_uuid)


#TESTME
def update_not_ip_address_scan_latest_state(
        scan_uuid=None,
        latest_state=None,
        org_uuid=None,
        ip_address_uuid=None,
):
    """
    Update all of the Elasticsearch documents that are not associated with the given
    IP address scan to have their is_latest_scan state set to latest_state.
    :param scan_uuid: The UUID of the IP address scan to filter on.
    :param latest_state: The status to set for is_latest_scan.
    :param org_uuid: The UUID of the organization to query.
    :param ip_address_uuid: The UUID of the IP address that the scan is associated with.
    :return: The Elasticsearch response.
    """
    query = IpAddressScanMultidocQuery()
    query.filter_by_not_ip_address_scan(scan_uuid)
    query.filter_by_ip_address(ip_address_uuid)
    query.update_field(key="is_latest_scan", value=latest_state)
    return query.update_by_query(org_uuid)
