# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import WsBaseResponse


class WsAdminManageUsersResponse(WsBaseResponse):
    """
        This is the auth response used to searilize user information for the UI
    """

    # Class Members

    # Instantiation
    def __init__(self, users):
        super(WsAdminManageUsersResponse, self).__init__()
        self.data['users'] = []

        for user in users:
            user_data = {
                'uuid': str(user.uuid),
                'email': user.email,
                'email_verified': user.email_verified,
                'enabled': user.account_manually_approved,
            }
            self.data['users'].append(user_data)

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
