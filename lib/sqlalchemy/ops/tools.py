# -*- coding: utf-8 -*-
from __future__ import absolute_import

from sqlalchemy import func

from lib import ConversionHelper
from ..models import ZmapConfig, NmapConfig


def does_nmap_config_name_exist(name=None, db_session=None):
    """
    Check to see whether a NmapConfig with the given name already exists.
    :param name: The name to check for.
    :param db_session: A SQLAlchemy session.
    :return: True if an NmapConfig with the given name already exists, False otherwise.
    """
    name = ConversionHelper.string_to_unicode(name)
    result = db_session.query(func.count(NmapConfig.uuid))\
        .filter(NmapConfig.name == name)\
        .one()
    return result[0] > 0


def does_zmap_config_name_exist(name=None, db_session=None):
    """
    Check to see whether a ZmapConfig with the given name already exists.
    :param name: The name to check for.
    :param db_session: A SQLAlchemy session.
    :return: True if a ZmapConfig with the given name exists, otherwise False.
    """
    result = db_session.query(func.count(ZmapConfig.uuid))\
        .filter(ZmapConfig.name == name)\
        .one()
    return result[0] > 0


def get_default_nmap_config(db_session):
    """
    Get the default NmapConfig object.
    :param db_session: A SQLAlchemy session.
    :return: The default NmapConfig object.
    """
    return get_nmap_config_by_name(name="default", db_session=db_session)


def get_default_zmap_config(db_session):
    """
    Get the default ZmapConfig object.
    :param db_session: A SQLAlchemy session.
    :return: The default ZmapConfig object.
    """
    return get_zmap_config_by_name(name="default", db_session=db_session)


def get_nmap_config_by_name(name=None, db_session=None):
    """
    Retrieve the NmapConfig object referenced by the given name.
    :param name: The name of the config to query for.
    :param db_session: A SQLAlchemy session.
    :return: The NmapConfig referenced by name.
    """
    name = ConversionHelper.string_to_unicode(name)
    return db_session.query(NmapConfig)\
        .filter(NmapConfig.name == name)\
        .one_or_none()


def get_zmap_config_by_name(name=None, db_session=None):
    """
    Retrieve the ZmapConfig object referenced by the given name.
    :param name: The name to query for.
    :param db_session: A SQLAlchemy session.
    :return: The ZmapConfig referenced by name.
    """
    name = ConversionHelper.string_to_unicode(name)
    return db_session.query(ZmapConfig)\
        .filter(ZmapConfig.name == name)\
        .one_or_none()
