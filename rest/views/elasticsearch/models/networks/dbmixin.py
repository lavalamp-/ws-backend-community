# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..mixin import BaseDbMixin
import rest.models


class IpAddressDbMixin(BaseDbMixin):
    """
    This is a mixin class for APIViews that rely on a parent IP address.
    """

    @classmethod
    def get_db_model_class(cls):
        return rest.models.IpAddress

    def _check_db_object_permissions(self):
        return self.db_object.network.organization.can_user_read(self.request.user)

    def _get_elasticsearch_index(self):
        return self.db_object.network.organization.uuid

    @property
    def mapped_elasticsearch_key(self):
        return "ip_address_uuid"
