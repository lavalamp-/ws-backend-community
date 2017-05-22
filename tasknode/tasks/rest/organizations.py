# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery.utils.log import get_task_logger

from ..base import DatabaseTask
from ...app import websight_app
from wselasticsearch import bootstrap_index_model_mappings
from wselasticsearch.helper import ElasticsearchHelper

logger = get_task_logger(__name__)


@websight_app.task(bind=True, base=DatabaseTask)
def handle_organization_deletion(self, org_uuid=None):
    """
    This task performs all of the necessary house keeping associated with the deletion of
    an organization.
    :param org_uuid: The UUID of the organization that was deleted.
    :return: None
    """
    logger.info(
        "Now handling deletion of organization %s."
        % (org_uuid,)
    )
    es_helper = ElasticsearchHelper.instance()
    es_helper.delete_index(org_uuid)
    logger.info(
        "Index %s deleted."
        % (org_uuid,)
    )


@websight_app.task(bind=True, base=DatabaseTask)
def initialize_organization(self, org_uuid=None):
    """
    This task performs all of the necessary initialization associated with the creation
    of a new organization.
    :param org_uuid: The UUID of the organization to perform initialization house keeping for.
    :return: None
    """
    logger.info(
        "Now performing initialization for organization %s."
        % (org_uuid,)
    )
    bootstrap_index_model_mappings(index=org_uuid, delete_first=True)
    logger.info(
        "Organization %s initialized."
        % (org_uuid,)
    )
