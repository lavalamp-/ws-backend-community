# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import ConversionHelper
from ..models import WsUser


def get_admin_emails(db_session):
    """
    Get a list containing the email address for all administrative users of Web Sight.
    :param db_session: A SQLAlchemy session.
    :return: A list containing the email address for all administrative users of Web Sight.
    """
    results = db_session.query(WsUser.email).filter(WsUser.is_superuser == True).all()
    return [result[0] for result in results]


def get_name_email_and_verification_token_for_user(user_uuid=None, db_session=None):
    """
    Get a tuple containing (1) the user name, (2) the user email, and (3) the user verification token
    for the user associated with the given UUID.
    :param user_uuid: The UUID of the user to retrieve results for.
    :param db_session: A SQLAlchemy session.
    :return: A tuple containing (1) the user name, (2) the user email, and (3) the user verification token
    for the user associated with the given UUID.
    """
    user_uuid = ConversionHelper.string_to_unicode(user_uuid)
    result = db_session.query(WsUser.first_name, WsUser.email, WsUser.email_registration_code)\
        .filter(WsUser.uuid == user_uuid)\
        .one()
    return tuple(result)


def get_user_activation_token(user_uuid=None, db_session=None):
    """
    Get the activation token associated with the given user.
    :param user_uuid: The UUID of the user to retrieve the activation token for.
    :param db_session: A SQLAlchemy session.
    :return: The activation token value associated with the given user.
    """
    user_uuid = ConversionHelper.string_to_unicode(user_uuid)
    result = db_session.query(WsUser.email_registration_code)\
        .filter(WsUser.uuid == user_uuid)\
        .one()
    return result[0]


def get_user_by_username(username=None, db_session=None):
    """
    Get the WsUser object by the given username.
    :param username: The username of the user to retrieve.
    :param db_session: A SQLALchemy session.
    :return: The WsUser object corresponding to the given username.
    """
    username = ConversionHelper.string_to_unicode(username)
    return db_session.query(WsUser)\
        .filter(WsUser.username == username)\
        .one_or_none()


def get_user_uuid_by_username(username=None, db_session=None):
    """
    Get the UUID of the given WsUser object by the given username.
    :param username: The username of the user to retrieve the UUID for.
    :param db_session: A SQLAlchemy session.
    :return: The UUID of user corresponding to username if such a user exists, otherwise None.
    """
    username = ConversionHelper.string_to_unicode(username)
    results = db_session.query(WsUser.uuid)\
        .filter(WsUser.username == username)\
        .one_or_none()
    return results[0] if results is not None else None
