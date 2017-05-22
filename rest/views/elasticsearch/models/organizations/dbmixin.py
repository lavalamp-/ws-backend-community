# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..mixin import BaseDbMixin


class OrganizationDbMixin(BaseDbMixin):
    """
    This is a mixin class for APIViews that rely on a parent organization.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_db_model_class(cls):
        from rest.models import Organization
        return Organization

    # Public Methods

    # Protected Methods

    def _check_db_object_permissions(self):
        return self.db_object.can_user_read(self.request.user)

    def _get_elasticsearch_index(self):
        return self.db_object.uuid

    # Private Methods

    # Properties

    @property
    def mapped_elasticsearch_key(self):
        return "org_uuid"

    # Representation and Comparison
