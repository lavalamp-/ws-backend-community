# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
import json

from .config import ConfigManager
from .filesystem import FilesystemHelper

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


def bootstrap_all_database_models():
    """
    Ensure that all of the necessary database objects are present in the Web Sight
    database.
    :return: None
    """
    bootstrap_nmap_configs()
    bootstrap_zmap_configs()


def bootstrap_data_stores():
    """
    Perform all of the necessary bootstrapping to set up all database and Elasticsearch
    content.
    :return: None
    """
    bootstrap_all_database_models()
    bootstrap_elasticsearch()


def bootstrap_django_models():
    """
    Perform the bootstrapping necessary to use Aldjemy outside of Django.
    :return: None
    """
    import os
    import django
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", config.django_settings_module)
    django.setup()


def bootstrap_elasticsearch():
    """
    Bootstrap Elasticsearch to contain the proper document typings.
    :return: None
    """
    from wselasticsearch.bootstrap import create_user_info_index, update_model_mappings
    update_model_mappings()
    create_user_info_index()


def bootstrap_zmap_configs():
    """
    Ensure that all of the default ZmapConfig objects are currently in the database.
    :return: None
    """
    from .sqlalchemy import get_sa_session, ZmapConfig
    from .sqlalchemy.ops import does_zmap_config_name_exist
    session = get_sa_session()
    if does_zmap_config_name_exist(name="default", db_session=session):
        logger.debug("ZmapConfig with name 'default' already exists. Skipping addition.")
    else:
        default_config = ZmapConfig.new(
            name="default",
            bandwidth="10M",
        )
        session.add(default_config)
        logger.debug("Added 'default' ZmapConfig.")
    session.commit()
    session.close()
    logger.debug("Completed bootstrapping of ZmapConfig objects.")


def bootstrap_nmap_configs():
    """
    Ensure that all of the default Nmapconfig objects are currently in the database.
    :return: None
    """
    from .sqlalchemy import get_sa_session, NmapConfig, does_nmap_config_name_exist
    session = get_sa_session()
    if does_nmap_config_name_exist(name="default", db_session=session):
        logger.debug("NmapConfig with name 'default' already exists. Skipping addition.")
    else:
        default_config = NmapConfig.new(
            name="default",
            speed=4,
            output_type="all",
            fingerprinting_enabled=False,
            resolution_enabled=False,
            host_discovery_enabled=False,
        )
        session.add(default_config)
        session.commit()
    session.close()
    logger.debug("Completed bootstrapping of NmapConfig objects.")
