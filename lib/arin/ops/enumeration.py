# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from ..request import OrganizationsArinRequest


def create_networks_csv_file_for_org(org_name=None, file_path=None, org_search_handle=None):
    """
    Create a CSV file containing all of the CIDR ranges owned by all organizations matching the given
    search handle and write the contents of the file to the given file path.
    :param org_name: The name of the organization to create the CSV file for.
    :param file_path: The file path to write the CSV file to.
    :param org_search_handle: A search term to search for organizations via.
    :return: None
    """
    networks = get_networks_by_organization_search(org_search_handle)
    cidr_ranges = []
    for network in networks:
        cidr_ranges.extend(network.cidr_ranges)
    csv_lines = []
    for index, cidr_range in enumerate(cidr_ranges):
        csv_lines.append("%s %s, %s, %s" % (org_name, index + 1, cidr_range.network, cidr_range.prefixlen))
    with open(file_path, "w+") as f:
        f.write("\n".join(csv_lines))


def get_networks_by_organization_search(org_search_handle):
    """
    Get a list of all the networks associated with organizations discovered via the given organization search handle.
    :param org_search_handle: A string depicting the term to search by.
    :return: A list of networks to owned by all organizations found through searching for the given search handle.
    """
    org_search_response = OrganizationsArinRequest.search_by_name(org_search_handle)
    logging.info(
        "A total of %s organizations were found for search term %s."
        % (len(org_search_response.organizations), org_search_handle)
    )
    networks = []
    for org in org_search_response.organizations:
        logging.info(
            "Now retrieving networks for organization %s..."
            % (org.name,)
        )
        networks.extend(org.nets)
        logging.info(
            "A total of %s networks were found for organization %s."
            % (len(org.nets), org.name)
        )
    logging.info(
        "All networks (%s total) retrieved for search term %s."
        % (len(networks), org_search_handle)
    )
    return networks
