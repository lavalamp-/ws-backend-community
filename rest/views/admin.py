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

class AdminManageUsersView(APIView):
    """
     This view is used get all users for the manage users admin page
    """
    throttle_classes = ()
    permission_classes = [
        IsAdminUser
    ]
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = AdminManageUsersSerializer

    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        users = serializer.validated_data['users']
        response = WsAdminManageUsersResponse(users)
        return Response(response.data)


class AdminManageUsersEnableDisableView(APIView):
    """
     This view is used to enable or disable a user in the system
    """
    throttle_classes = ()
    permission_classes = [
        IsAdminUser
    ]
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = AdminManageUsersEnableDisableSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({})


class AdminManageUsersDeleteUserView(APIView):
    """
     This view is used to delete a user in the system
    """
    throttle_classes = ()
    permission_classes = [
        IsAdminUser
    ]
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = AdminManageUsersDeleteUserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({})


class AdminManageUsersResendVerificationEmailView(APIView):
    """
     This view is used to re-send a email verification email for a user in the system
    """
    throttle_classes = ()
    permission_classes = [
        IsAdminUser
    ]
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = AdminManageUsersResendVerificationEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({})