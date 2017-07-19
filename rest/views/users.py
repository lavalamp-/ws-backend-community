# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404

from rest_framework import viewsets, permissions, status
from rest_framework.decorators import api_view
from rest_framework.exceptions import MethodNotAllowed, ParseError, NotFound
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from rest.serializers import UserSerializer
from rest.serializers.users import VerifyEmailSerializer, ForgotPasswordSerializer, \
    VerifyForgotPasswordSerializer, SetupAccountSerializer
from wselasticsearch.models import UserOrganizationSelectModel
from wselasticsearch.query import UserOrganizationSelectQuery
from .base import WsCreateAPIView, BaseWsGenericAPIView
from rest.models import Organization
from lib import ConfigManager

UserModel = get_user_model()
config = ConfigManager.instance()


class UserCreateView(WsCreateAPIView):
    """
    Create a new user account.
    """

    permission_classes = [permissions.AllowAny]

    serializer_class = UserSerializer


class VerifyEmailView(BaseWsGenericAPIView):
    """
    Verify an email address.
    """
    permission_classes = [
        AllowAny
    ]

    serializer_class = VerifyEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(data={}, status=status.HTTP_200_OK)


class SetupAccountView(BaseWsGenericAPIView):
    """
    post:
    Set up an account (typically performed in relation to an email invite).
    """
    permission_classes = [
        AllowAny
    ]

    serializer_class = SetupAccountSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(status=status.HTTP_200_OK)


class ForgotPasswordView(BaseWsGenericAPIView):
    """
    Submit a forgot password request.
    """

    permission_classes = [
        AllowAny
    ]

    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(status=status.HTTP_200_OK)


class VerifyForgotPasswordView(BaseWsGenericAPIView):
    """
    Fulfill a change password request as a result of a forgot password request.
    """
    permission_classes = [
        AllowAny
    ]

    serializer_class = VerifyForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(status=status.HTTP_200_OK)
