# -*- coding: utf-8 -*-
from __future__ import absolute_import

from wselasticsearch.query import DomainNameMultidocQuery
from wselasticsearch.query import DomainNameScanMultidocQuery


def get_all_domain_names_for_organization(org_uuid):
    """
    Get a list containing all of the domain names ever found for the given organization.
    :param org_uuid: The UUID of the organization to retrieve domain names for.
    :return: A list containing all of the domain names ever found for the given organization.
    """
    query = DomainNameMultidocQuery(size=None, offset=None)
    query.filter_by_organization(org_uuid)
    query.queried_fields = "domain_names"
    response = query.search(org_uuid)
    domain_names = response.get_field_from_results("domain_names")
    to_return = []
    for entry in domain_names:
        to_return.extend(entry)
    return list(set(to_return))


def update_domain_name_scan_latest_state(scan_uuid=None, latest_state=None, org_uuid=None):
    """
    Update all of the Elasticsearch documents associated with the given domain name scan to
    have their is_latest_scan state set to latest_state.
    :param scan_uuid: The UUID of the domain name scan to update.
    :param latest_state: The status to set for is_latest_scan.
    :param org_uuid: The UUID of the organization to query.
    :return: The Elasticsearch response.
    """
    query = DomainNameScanMultidocQuery()
    query.filter_by_domain_name_scan(scan_uuid)
    query.update_field(key="is_latest_scan", value=latest_state)
    return query.update_by_query(org_uuid)


def update_not_domain_name_scan_latest_state(
        scan_uuid=None,
        latest_state=None,
        org_uuid=None,
        domain_uuid=None,
):
    """
    Update all of the Elasticsearch documents that are not associated with the given
    domain name scan to have their is_latest_scan state set to latest_state.
    :param scan_uuid: The UUID of the domain name scan to filter on.
    :param latest_state: The status to set for is_latest_scan.
    :param org_uuid: The UUID of the organization to query.
    :param domain_uuid: The UUID of the domain name that the scan is associated with.
    :return: The Elasticsearch response.
    """
    query = DomainNameScanMultidocQuery()
    query.filter_by_not_domain_name_scan(scan_uuid)
    query.filter_by_domain_name(domain_uuid)
    query.update_field(key="is_latest_scan", value=latest_state)
    return query.update_by_query(org_uuid)
