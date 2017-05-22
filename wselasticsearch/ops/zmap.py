# -*- coding: utf-8 -*-
from __future__ import absolute_import

from wselasticsearch.query import ZmapScanResultQuery
from wselasticsearch.helper import ElasticsearchHelper

es_helper = ElasticsearchHelper.instance()


def count_ports_scanned_for_organization(org_uuid=None, index=None):
    """
    Count how many times each port has been scanned for the given organization.
    :param org_uuid: The UUID of the organization to search for.
    :param index: The index to search in.
    :return:
    """
    query = ZmapScanResultQuery(suppress_source=True)
    query.must_by_term(key="organization_uuid", value=org_uuid)
    query.aggregate_on_term(key="port", name="port_count")
    return query.search(index=index)


def get_zmap_results_for_organization(org_uuid=None, index=None):
    """
    Get all of the ZmapResultModel instances for the given organization.
    :param org_uuid: The UUID of the organization to search for.
    :param index: The index to search in.
    :return: All of the ZmapResultModel instances for the given organization.
    """
    query = ZmapScanResultQuery()
    query.must_by_term(key="organization_uuid", value=org_uuid)
    return query.search(index=index)


def get_zmap_results_for_organization_and_port(org_uuid=None, port=None, index=None):
    """
    Get all of the ZmapResultModel instances for the given organization and the given port.
    :param org_uuid: The UUID of the organization to search for.
    :param port: The port to search for.
    :param index: The index to search in.
    :return: All of the ZmapResultModel instances for the given organization and port.
    """
    query = ZmapScanResultQuery()
    query.must_by_term(key="organization_uuid", value=org_uuid)
    query.must_by_term(key="port", value=port)
    return query.search(index=index)
