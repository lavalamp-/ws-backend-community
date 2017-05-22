# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from wselasticsearch.query import AllElasticsearchQuery
from ..base import DatabaseTask
from ...app import websight_app

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=DatabaseTask)
def handle_network_deletion(self, network_uuid=None, org_uuid=None):
    """
    This task performs all of the necessary house keeping associated with the deletion of a network.
    :param network_uuid: The UUID of the network that was deleted.
    :param org_uuid: The UUID of the organization that the network was deleted from.
    :return: None
    """
    logger.info(
        "Now handling deletion of network %s."
        % (network_uuid,)
    )
    query = AllElasticsearchQuery()
    query.must_by_term(key="network_uuid", value=network_uuid)
    query.delete_by_query(org_uuid)
    logger.info(
        "All data associated with network %s deleted from Elasticsearch."
        % (network_uuid,)
    )
