# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseMappedElasticsearchModel
from ..types import *


class BaseUserModel(BaseMappedElasticsearchModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a given user.
    """

    # Class Members

    user_uuid = KeywordElasticsearchType(
        help_text="The UUID of the user that the contents of this model are in reference to.",
    )

    # Instantiation

    def __init__(self, user_uuid=None):
        super(BaseUserModel, self).__init__()
        self.user_uuid = user_uuid

    # Static Methods

    # Class Methods

    @classmethod
    def get_can_populate_dummy(cls):
        return True

    @classmethod
    def get_has_mapped_parent(cls):
        return False

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import WsUser
        return WsUser

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.uuid = WsFaker.create_uuid()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.user_uuid = database_model.uuid
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.user_uuid)

