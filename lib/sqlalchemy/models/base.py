# -*- coding: utf-8 -*-
from __future__ import absolute_import

from uuid import uuid4
from datetime import datetime

from lib import ConversionHelper


def from_django_model(model_class):
    """
    Create an augmented Aldjemy SQLAlchemy class from the given Django model class.
    :param model_class: The model class to create an augmented Aldjemy class from.
    :return: The augmented Aldjemy class.
    """
    to_return = model_class.sa
    to_return.new = new_model_instance
    to_return.by_uuid = by_uuid
    to_return.update_from_dict = update_from_dict
    return to_return


@classmethod
def new_model_instance(cls, *args, **kwargs):
    """
    This is a drop-in method for creating new SQLAlchemy Aldjemy models.
    :param args: Positional arguments.
    :param kwargs: Key-value mappings for the model properties.
    :return: A new instance of the configured class.
    """
    to_return = cls()
    to_return.created = datetime.now()
    if "uuid" not in kwargs:
        to_return.uuid = unicode(uuid4())
    for k, v in kwargs.iteritems():
        setattr(to_return, k, v)
    return to_return


@classmethod
def by_uuid(cls, db_session=None, uuid=None, raise_error=True):
    """
    This is a drop-in method for retrieving database model instances by UUID.
    :param db_session: A SQLAlchemy session.
    :param uuid: The UUID to query.
    :param raise_error: Whether or not to raise an error if an object matching the UUID
    is not found.
    :return: An instance of cls retrieved from the database with the given UUID.
    """
    uuid = ConversionHelper.string_to_unicode(uuid)
    query = db_session.query(cls).filter(getattr(cls, "uuid") == uuid)
    if raise_error:
        return query.one()
    else:
        return query.one_or_none()


def update_from_dict(self, update_dict):
    """
    This is a drop-in method for updating the contents of a database model instance based on
    the contents of the given dictionary.
    :param update_dict: A dictionary containing key-value pairs to update self with.
    :return: None
    """
    for k, v in update_dict.iteritems():
        setattr(self, k, v)
