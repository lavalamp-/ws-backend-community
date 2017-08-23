# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..models import DefaultFlag, OrganizationFlag
from lib import ConversionHelper


def get_all_flags_for_organization_by_applies_to(db_session=None, applies_to=None, org_uuid=None):
    """
    Get a list containing all of the flags owned by the given organization and default flags that match
    the given applies_to value.
    :param db_session: A SQLAlchemy session.
    :param applies_to: A string depicting what the flag applies to.
    :param org_uuid: The UUID of the organization to query.
    :return: A list containing all of the flags owned by the given organization and default flags that match
    the given applies_to value.
    """
    to_return = get_default_flags_by_applies_to(db_session=db_session, applies_to=applies_to)
    to_return.extend(get_organization_flags_by_applies_to(
        db_session=db_session,
        applies_to=applies_to,
        org_uuid=org_uuid,
    ))
    return_map = {}
    for flag in to_return:
        return_map[flag.tag] = flag
    return return_map.values()


#TESTME
def get_all_ip_flags_for_organization(db_session=None, org_uuid=None):
    """
    Get a list containing all of the flags owned by the given organization and default flags that apply to
    IP addresses.
    :param db_session: A SQLAlchemy session.
    :param org_uuid: The UUID of the organization to query.
    :return: A list containing all of the flags owned by the given organization and default flags that apply to
    IP addresses.
    """
    return get_all_flags_for_organization_by_applies_to(db_session=db_session, org_uuid=org_uuid, applies_to="ip")


#TESTME
def get_all_ssl_flags_for_organization(db_session=None, org_uuid=None):
    """
    Get a list containing all of the flags owned by the given organization and default flags that apply to
    SSL services.
    :param db_session: A SQLAlchemy session.
    :param org_uuid: The UUID of the organization to query.
    :return: A list containing all of the flags owned by the given organization and default flags that apply to
    SSL services.
    """
    return get_all_flags_for_organization_by_applies_to(db_session=db_session, org_uuid=org_uuid, applies_to="ssl")


#TESTME
def get_all_web_flags_for_organization(db_session=None, org_uuid=None):
    """
    Get a list containing all of the flags owned by the given organization and default flags that apply to
    web services.
    :param db_session: A SQLAlchemy session.
    :param org_uuid: The UUID of the organization to query.
    :return: A list containing all of the flags owned by the given organization and default flags that apply to
    web services.
    """
    return get_all_flags_for_organization_by_applies_to(db_session=db_session, org_uuid=org_uuid, applies_to="web")


def get_default_flags_by_applies_to(db_session=None, applies_to=None):
    """
    Get all of the default flag objects in the database that apply to the given string.
    :param db_session: A SQLAlchemy session.
    :param applies_to: A string describing the type of Elasticsearch data that the flags apply to.
    :return: A list containing all of the default flag objects in the database that apply to the
    given string.
    """
    applies_to = ConversionHelper.string_to_unicode(applies_to)
    return db_session.query(DefaultFlag)\
        .filter(DefaultFlag.applies_to == applies_to)\
        .all()


def get_organization_flags_by_applies_to(db_session=None, applies_to=None, org_uuid=None):
    """
    Get all of the organization flag objects in the database that apply to the given string.
    :param db_session: A SQLAlchemy session.
    :param applies_to: A string describing the type of Elasticsearch data that the flags apply to.
    :param org_uuid: The UUID of the organization to retrieve organization flags for.
    :return: A list containing all of the organization flag objects in the database that apply to the
    given string.
    """
    applies_to = ConversionHelper.string_to_unicode(applies_to)
    org_uuid = ConversionHelper.string_to_unicode(org_uuid)
    return db_session.query(OrganizationFlag) \
        .filter(OrganizationFlag.applies_to == applies_to) \
        .filter(OrganizationFlag.organization_id == org_uuid) \
        .all()
