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
from .base import WsCreateAPIView
from rest.models import Organization
from lib import ConfigManager

UserModel = get_user_model()
config = ConfigManager.instance()


class UserCreateView(WsCreateAPIView):
    """
    API endpoint for creating new users.
    """

    permission_classes = [permissions.AllowAny]

    serializer_class = UserSerializer


class VerifyEmailView(APIView):
    """
    API endpoint that allows a user to verify their email
    """
    permission_classes = [
        AllowAny
    ]

    serializer_class = VerifyEmailSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(data={}, status=status.HTTP_200_OK)


class SetupAccountView(APIView):
    """
    API endpoint that allows a user to verify their email
    """
    permission_classes = [
        AllowAny
    ]

    serializer_class = SetupAccountSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(status=status.HTTP_200_OK)


class ForgotPasswordView(APIView):
    """
    API endpoint that allows a user to recover their forgotten password
    """
    permission_classes = [
        AllowAny
    ]

    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(status=status.HTTP_200_OK)


class VerifyForgotPasswordView(APIView):
    """
    API endpoint that allows a user to actually change thier password,
        consuming thier one-time token they they were emailed
    """
    permission_classes = [
        AllowAny
    ]

    serializer_class = VerifyForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(status=status.HTTP_200_OK)


@api_view(["GET", "POST"])
def selected_organization(request):
    """
    This is a simple view for keeping track of the organizations that a user has
    selected.
    :param request: The request that resulted in invocation of this method.
    :return: A Django request object.
    """

    if request.method == "GET":
        query = UserOrganizationSelectQuery(size=3)
        query.filter_by_user(request.user.uuid)
        query.sort_by_selected()
        response = query.search(config.es_user_info_index)
        to_return = []
        for result in response.results:
            to_return.append({
                "uuid": result["_source"]["org_uuid"],
                "name": result["_source"]["org_name"],
            })
        return Response(to_return, status=200)
    elif request.method == "POST":
        if "uuid" not in request.data:
            raise ParseError("No UUID found in request body.")
        try:
            organization = get_object_or_404(Organization, pk=request.data["uuid"])
        except ValueError:
            raise ParseError("Invalid UUID.")
        if not request.user.is_superuser and not organization.can_user_read(request.user):
            raise NotFound()
        select = UserOrganizationSelectModel(
            user_uuid=request.user.uuid,
            org_uuid=organization.uuid,
            org_name=organization.name,
        )
        select.save(config.es_user_info_index)
        return Response(status=204)
    else:
        raise MethodNotAllowed(method=request.method)
