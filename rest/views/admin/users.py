# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseAdminWsListAPIView, BaseAdminWsGenericAPIView
from rest_framework.response import Response

import rest.serializers
import rest.models


class AdminManageUsersView(BaseAdminWsListAPIView):
    """
    get:
    Get a list of all of the registered users.
    """

    serializer_class = rest.serializers.AdminManageUsersSerializer

    def get_queryset(self):
        return rest.models.WsUser.objects.all()


class AdminManageUsersEnableDisableView(BaseAdminWsGenericAPIView):
    """
    post:
    Enable or disable the specified user.
    """

    serializer_class = rest.serializers.AdminManageUsersEnableDisableSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({})


class AdminManageUsersDeleteUserView(BaseAdminWsGenericAPIView):
    """
    post:
    Delete the specified user.
    """

    serializer_class = rest.serializers.AdminManageUsersDeleteUserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({})


class AdminManageUsersResendVerificationEmailView(BaseAdminWsGenericAPIView):
    """
    post:
    Re-send the verification email to the specified user.
    """

    serializer_class = rest.serializers.AdminManageUsersResendVerificationEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({})
