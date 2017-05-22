# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.contrib.auth.models import AnonymousUser

from .base import WsBaseResponse


class WsAuthResponse(WsBaseResponse):
    """
        This is the auth response used to searilize user information for the UI
    """

    # Class Members

    # Instantiation
    def __init__(self, ws_user, token):
        super(WsAuthResponse, self).__init__()
        self.data['token'] = None
        self.data['is_admin'] = False
        self.data['is_authenticated'] = False
        self.data["user_uuid"] = None
        self.data["is_enterprise_user"] = False

        if token:
            self.data['token'] = token.key

        if ws_user:
            self.data['is_admin'] = bool(ws_user.is_superuser)
            self.data['is_authenticated'] = bool(ws_user.is_authenticated)
            if not isinstance(ws_user, AnonymousUser):
                self.data["user_uuid"] = ws_user.uuid
                self.data["is_enterprise_user"] = ws_user.is_enterprise_user

        self.data['groups'] = []

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
