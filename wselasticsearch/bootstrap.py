# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from lib import ConfigManager

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


def create_user_info_index():
    """
    Create the index for storing user information.
    :return: None
    """
    bootstrap_index_model_mappings(index=config.es_user_info_index, delete_first=True)


def bootstrap_index_model_mappings(index=None, delete_first=True):
    """
    Bootstrap index model mappings for the given index.
    :param index: The index to set mappings for.
    :param delete_first: Whether or not to delete the index first.
    :return: None
    """
    from lib import WsIntrospectionHelper
    from wselasticsearch.helper import ElasticsearchHelper
    es_helper = ElasticsearchHelper.instance()
    if delete_first:
        indices = es_helper.get_indices()
        if index in indices:
            es_helper.delete_index(index)
        es_helper.create_index(index)
    model_tuples = WsIntrospectionHelper.get_elasticsearch_model_classes()
    for name, model_class in model_tuples:
        logger.debug("Updating mapping for class %s." % (name,))
        model_class.update_mapping(index)
    logger.debug("All Elasticsearch model mappings updated!")


def update_model_mappings(delete_first=True):
    """
    Update all of the model mappings in the Elasticsearch backend.
    :param delete_first: Whether or not to delete all existing mappings first.
    :return: None
    """
    from lib import ConfigManager
    config = ConfigManager.instance()
    bootstrap_index_model_mappings(index=config.es_default_index, delete_first=delete_first)
