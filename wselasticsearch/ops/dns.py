# -*- coding: utf-8 -*-
from __future__ import absolute_import

from wselasticsearch.query import DnsRecordQuery, SubdomainEnumerationQuery


def get_all_domains_for_ip_address(org_uuid=None, ip_address=None, filter_by_latest=True):
    """
    Get a list of strings representing all of the domains associated with the given IP address as found
    for the given organization.
    :param org_uuid: The UUID of the organization to query for.
    :param ip_address: The IP address to query against.
    :param filter_by_latest: Whether or not to filter results to only those that were gathered during most
    recent domain name scans.
    :return: A list of strings representing all of the domains associated with the given IP address as found
    for the given organization.
    """
    query = DnsRecordQuery(max_size=True)
    query.filter_by_ip_address(ip_address)
    if filter_by_latest:
        query.filter_by_latest_scan()
    query.queried_fields = ["domain_name"]
    response = query.search(org_uuid)
    to_return = set()
    for result in response.results:
        to_return.add(result["_source"]["domain_name"])
    to_return.add(ip_address)
    return list(to_return)


def get_all_subdomains_from_domain_scan_enumeration(org_uuid=None, parent_domain=None, domain_scan_uuid=None):
    """
    Get a list containing all of the subdomains that were found for the given parent domain during the given
    domain name scan.
    :param org_uuid: The UUID of the organization to query.
    :param parent_domain: The parent domain to retrieve results for.
    :param domain_scan_uuid: The UUID of the domain name scan to retrieve results for.
    :return: A list containing all of the subdomains that were found for the given parent domain during the given
    domain name scan.
    """
    to_return = []
    query = SubdomainEnumerationQuery(max_size=True)
    query.filter_by_parent_domain(parent_domain)
    query.filter_by_enumeration_method("dnsdb")
    response = query.search(org_uuid)
    for result in response.results:
        to_return.extend(result["_source"]["child_domains"])
    return list(set(to_return))


def get_all_user_added_domain_names_for_organization(org_uuid=None, filter_by_latest=True):
    """
    Get a list of strings representing every domain name that a user has added to the given organization.
    :param org_uuid: The UUID of the organization to query.
    :param filter_by_latest: Whether or not to filter results to only the results of the latest scans.
    :return: A list of strings representing every domain name that a user has added to the given organization.
    """
    query = DnsRecordQuery(max_size=True)
    query.filter_by_user_domain()
    if filter_by_latest:
        query.filter_by_latest_scan()
    query.queried_fields = ["domain_name"]
    response = query.search(org_uuid)
    to_return = set()
    for result in response.results:
        to_return.add(result["_source"]["domain_name"])
    return list(to_return)


def get_ip_addresses_from_domain_name_scan(domain_scan_uuid=None, org_uuid=None):
    """
    Get a list of the IP addresses that were discovered during the given domain name scan.
    :param domain_scan_uuid: The UUID of the domain name scan to retrieve IP addresses for.
    :param org_uuid: The UUID of the organization to query for.
    :return: A list of the IP addresses that were discovered during the given domain name scan.
    """
    query = DnsRecordQuery()
    query.filter_by_domain_name_scan(domain_scan_uuid)
    query.filter_by_contains_ip_address()
    query.queried_fields = ["record_content"]
    results = query.search(org_uuid)
    return results.get_field_from_results("record_content")
