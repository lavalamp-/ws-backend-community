# -*- coding: utf-8 -*-
from __future__ import absolute_import

from sqlalchemy import func

from lib import ConversionHelper


def count_model_instances(db_class=None, db_session=None):
    """
    Count the number of instances of the specified database model class exist within the configured
    database.
    :param db_class: The database model class to count.
    :param db_session: A SQLAlchemy session to use to query a database.
    :return: The number of instances of the specified database model class exist within the configured
    database.
    """
    return db_session.query(func.count(getattr(db_class, "uuid"))).one()[0]


def does_model_instance_exist(db_class=None, uuid=None, db_session=None):
    """
    Check to see if an instance of the specified database model class exists within the
    configured database with the specified UUID.
    :param db_class: The database class to check.
    :param uuid: The UUID to look for.
    :param db_session: A SQLAlchemy session to use to query a database.
    :return: True if an instance of the specified model exists with the UUID, False otherwise.
    """
    result = db_session\
        .query(func.count(db_class.uuid))\
        .filter(db_class.uuid == uuid)\
        .one()
    return result[0] > 0


def is_unique_constraint_exception(exception):
    """
    Check to see if the given exception indicates that a unique constraint has been violated.
    :param exception: The SQLAlchemy integrity exception to check.
    :return: True if the given exception indicates that a unique constraint has been violated, False otherwise.
    """
    return "violates unique constraint" in exception.message


def update_model_instance(db_session=None, model_class=None, model_uuid=None, update_dict=None):
    """
    Update the given instance of the specified model class with the given dictionary.
    :param db_session: A SQLAlchemy session to use to query a database.
    :param model_class: The model class to query for.
    :param model_uuid: The UUID of the model instance to update.
    :param update_dict: A dictionary containing key-value pairs to update the referenced instance with.
    :return: None
    """
    model_uuid = ConversionHelper.string_to_unicode(model_uuid)
    db_session\
        .query(model_class)\
        .filter(getattr(model_class, "uuid") == model_uuid)\
        .update(update_dict)
