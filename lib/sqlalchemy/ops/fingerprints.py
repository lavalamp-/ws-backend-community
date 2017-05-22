# -*- coding: utf-8 -*-
from __future__ import absolute_import

from sqlalchemy import func

from lib import ConversionHelper
from ..models import HashFingerprint


def does_hash_fingerprint_exist(db_session=None, sha256_hash=None):
    """
    Check to see whether a HashFingeprint object matching the given sha256 hash already exists.
    :param db_session: A SQLAlchemy session.
    :param sha256_hash: The hash to check against.
    :return: True if a hash matching the given hash already exists, False otherwise.
    """
    sha256_hash = ConversionHelper.string_to_unicode(sha256_hash)
    result = db_session.query(func.count(HashFingerprint.uuid))\
        .filter(HashFingerprint.hash == sha256_hash)\
        .one()
    return result[0] > 0


def get_hash_fingerprints_for_apache_tomcat(db_session):
    """
    Get all of the HashFingerprint objects in the database that are associated with Apache Tomcat.
    :param db_session: A SQLAlchemy session.
    :return: A list containing all of the HashFingerprint objects in the database that are associated
    with Apache Tomcat.
    """
    return get_hash_fingerprints_for_es_attribute(db_session=db_session, es_attr="uses_tomcat_management_portal")


def get_hash_fingerprints_for_es_attribute(db_session=None, es_attr=None):
    """
    Get all of the HashFingerprint objects in the database that are associated with the given Elasticsearch
    attribute.
    :param db_session: A SQLAlchemy session.
    :param es_attr: The Elasticsearch attribute to search for.
    :return: A list containing all of the HashFingerprint objects in the database that are associated
    with the given Elasticsearch attribute.
    """
    es_attr = ConversionHelper.string_to_unicode(es_attr)
    return db_session.query(HashFingerprint).filter(HashFingerprint.es_attribute == es_attr).all()
