# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.contrib.auth import get_user_model

from rest_framework import status, parsers, renderers, authentication, exceptions
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAdminUser
from rest.serializers import AdminManageUsersSerializer, AdminManageUsersEnableDisableSerializer, AdminManageUsersDeleteUserSerializer, AdminManageUsersResendVerificationEmailSerializer
from rest.responses import WsAdminManageUsersResponse

from rest.models import WsUser
from .base import WsListAPIView, BaseWsAPIView, BaseWsGenericAPIView


class AdminManageUsersView(WsListAPIView):
    """
    get:
    Get a list of all of the registered users.
    """
    permission_classes = [
        IsAdminUser
    ]
    serializer_class = AdminManageUsersSerializer

    def get_queryset(self):
        return WsUser.objects.all()


class AdminManageUsersEnableDisableView(BaseWsGenericAPIView):
    """
    post:
    Enable or disable the specified user.
    """
    permission_classes = [
        IsAdminUser
    ]
    serializer_class = AdminManageUsersEnableDisableSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({})


class AdminManageUsersDeleteUserView(BaseWsGenericAPIView):
    """
    post:
    Delete the specified user.
    """
    permission_classes = [
        IsAdminUser
    ]

    serializer_class = AdminManageUsersDeleteUserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({})


class AdminManageUsersResendVerificationEmailView(BaseWsGenericAPIView):
    """
    post:
    Re-send the verification email to the specified user.
    """
    permission_classes = [
        IsAdminUser
    ]
    serializer_class = AdminManageUsersResendVerificationEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({})