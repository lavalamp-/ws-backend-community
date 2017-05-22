# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
import json

from .config import ConfigManager
from .filesystem import FilesystemHelper

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


def bootstrap_django_models():
    """
    Perform the bootstrapping necessary to use Aldjemy outside of Django.
    :return: None
    """
    import os
    import django
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", config.django_settings_module)
    django.setup()


def bootstrap_order_tiers():
    """
    Ensure that all of the default OrderTier objects are currently in the database.
    :return: None
    """
    from .sqlalchemy import get_sa_session, OrderTier
    session = get_sa_session()
    session.query(OrderTier).delete()
    file_contents = FilesystemHelper.get_file_contents(config.files_order_tiers_path)
    contents = json.loads(file_contents)
    for entry in contents:
        new_tier = OrderTier.new(**entry)
        session.add(new_tier)
    session.commit()


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
