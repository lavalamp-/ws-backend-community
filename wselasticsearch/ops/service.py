# -*- coding: utf-8 -*-
from __future__ import absolute_import

from wselasticsearch.query import SslSupportQuery, ServiceFingerprintQuery, VirtualHostFingerprintQuery, \
    VirtualHostQuery, SslSupportReportQuery, SslVulnerabilityQuery, SslCertificateQuery


def delete_ssl_inspection_documents_for_network_service_scan(network_service_scan_uuid=None, org_uuid=None):
    """
    Delete all of the documents associated with SSL support inspection that currently reside in Elasticsearch
    for the given network service scan.
    :param network_service_scan_uuid: The UUID of the network service scan to delete documents based off
    of.
    :param org_uuid: The UUID of the organization to delete documents for.
    :return: None
    """
    query = SslSupportReportQuery()
    query.filter_by_network_service_scan(network_service_scan_uuid)
    query.delete_by_query(org_uuid)
    query = SslVulnerabilityQuery()
    query.filter_by_network_service_scan(network_service_scan_uuid)
    query.delete_by_query(org_uuid)
    query = SslCertificateQuery()
    query.filter_by_network_service_scan(network_service_scan_uuid)
    query.delete_by_query(org_uuid)
    query = SslSupportQuery()
    query.filter_by_network_service_scan(network_service_scan_uuid)
    query.delete_by_query(org_uuid)


def does_network_service_scan_support_ssl(network_service_scan_uuid=None, org_uuid=None):
    """
    Check to see whether the results of the given network service scan indicate that the referenced
    network service currently supports SSL.
    :param network_service_scan_uuid: The UUID of the network service scan to check against.
    :param org_uuid: The UUID of the organization that owns the network service scan.
    :return: True if the results of the network service scan indicate that the service supports SSL,
    False otherwise.
    """
    ssl_version = get_supported_ssl_version_for_service(org_uuid=org_uuid, scan_uuid=network_service_scan_uuid)
    return ssl_version is not None


#TESTME
def get_fingerprint_data_for_network_service_scan(scan_uuid=None, org_uuid=None, over_ssl=None):
    """
    Get a list of tuples containing (1) the response code, (2) whether or not the response had content,
    (3) the response MIME type, (4) the response primary hash, (5) the response secondary hash, (6)
    whether or not SSL was used to access the web service, and (7) the hostname for all virtual host
    fingerprints gathered during the given network service scan.
    :param scan_uuid: The UUID of the network service scan to retrieve data for.
    :param org_uuid: The UUID of the organization to retrieve data for.
    :param over_ssl: If set to True or False, filter results based on whether or not they were observed
    over SSL. If left as None, don't apply a filter.
    :return: a list of tuples containing (1) the response code, (2) whether or not the response had content,
    (3) the response MIME type, (4) the response primary hash, (5) the response secondary hash, (6)
    whether or not SSL was used to access the web service, and (7) the hostname for all virtual host
    fingerprints gathered during the given network service scan.
    """
    queried_fields = [
        "response_code",
        "response_has_content",
        "response_mime_type",
        "response_primary_hash",
        "response_secondary_hash",
        "over_ssl",
        "hostname",
    ]
    query = VirtualHostFingerprintQuery(max_size=True)
    query.filter_by_organization(org_uuid)
    query.filter_by_network_service_scan(scan_uuid)
    if over_ssl is not None:
        query.filter_by_over_ssl(over_ssl)
    query.queried_fields = queried_fields
    response = query.search(index=org_uuid)
    return response.get_fields_from_results(queried_fields)


def get_latest_ssl_support_report_ids(org_uuid):
    """
    Get a list of strings containing all of the IDs associated with all of the latest SSL support reports associated
    with the given organization.
    :param org_uuid: The UUID of the organization to get Elasticsearch IDs for.
    :return: A list of strings containing all of the IDs associated with all of the latest SSL support reports
    associated with the given organization.
    """
    query = SslSupportReportQuery(max_size=True, suppress_source=True)
    query.filter_by_latest_scan()
    response = query.search(org_uuid)
    return [x["_id"] for x in response.results]


def get_network_service_scan_uuid_from_ssl_report_id(org_uuid=None, report_id=None):
    """
    Get the network service scan UUID from the given SSL support report.
    :param org_uuid: The UUID of the organization to retrieve data for.
    :param report_id: The ID of the SSL support report document to retrieve.
    :return: The network service scan UUID for the given SSL support report.
    """
    query = SslSupportReportQuery(max_size=True)
    query.queried_fields = ["network_service_scan_uuid"]
    response = query.get(index=org_uuid, doc_id=report_id)
    return response.network_service_scan_uuid


#TESTME
def get_successful_fingerprints_for_service(
        org_uuid=None,
        scan_uuid=None,
        service_uuid=None,
):
    """
    Get a list containing all of the fingerprinted service names that were successfully found
    on the referenced serviced during the given scan.
    :param org_uuid: The organization UUID to filter on.
    :param scan_uuid: The scan UUID to filter on.
    :param service_uuid: The UUID of the network service to filter on.
    :return: A list containing all of the fingerprinted service names that were successfully found
    on the referenced serviced during the given scan.
    """
    query = ServiceFingerprintQuery()
    query.filter_by_organization(org_uuid)
    query.filter_by_network_service_scan(scan_uuid)
    query.filter_by_network_service(service_uuid)
    query.filter_by_successful_fingerprints()
    query.queried_fields = "fingerprint_name"
    response = query.search(index=org_uuid)
    return response.get_field_from_results("fingerprint_name")


def get_supported_ssl_versions_for_service(org_uuid=None, scan_uuid=None):
    """
    Get a list containing all supported SSL version for the given network service, scan, and organization.
    :param org_uuid: The organization UUID to filter on.
    :param scan_uuid: The scan UUID to filter on.
    :return: A list containing all supported SSL version for the given network service, scan, and organization.
    """
    query = SslSupportQuery()
    query.filter_by_organization(org_uuid)
    query.filter_by_network_service_scan(scan_uuid)
    query.must_by_term(key="supported", value=True)
    query.queried_fields = "pyopenssl_protocol"
    response = query.search(index=org_uuid)
    return response.get_field_from_results("pyopenssl_protocol")


#TESTME
def get_supported_ssl_version_for_service(org_uuid=None, scan_uuid=None):
    """
    Get a supported SSL version for the given network service, scan, and organization.
    :param org_uuid: The organization UUID to filter on.
    :param scan_uuid: The scan UUID to filter on.
    :return: A supported SSL version for the given network service, scan, and organization if such an SSL
    version exists, otherwise None.
    """
    supported_versions = get_supported_ssl_versions_for_service(
        org_uuid=org_uuid,
        scan_uuid=scan_uuid,
    )
    return supported_versions[0] if len(supported_versions) > 0 else None


#TESTME
def get_virtual_hosts_from_network_service_scan(scan_uuid=None, org_uuid=None):
    """
    Get a list of all of the virtual hosts discovered during the given network service scan.
    :param scan_uuid: The UUID of the network service scan to retrieve virtual hosts for.
    :param org_uuid: The UUID of the organization to query.
    :return: A list of all of the virtual hosts discovered during the given network service scan.
    """
    query = VirtualHostQuery(max_size=True)
    query.filter_by_network_service_scan(scan_uuid)
    query.queried_fields = ["hostname"]
    results = query.search(org_uuid)
    return results.get_field_from_results("hostname")
