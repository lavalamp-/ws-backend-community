# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.contrib.auth import get_user_model

from rest_framework import status, parsers, renderers, authentication, exceptions
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest.serializers import WsAuthTokenSerializer
from rest.responses import  WsAuthResponse

from .base import BaseWsGenericAPIView


class WsTokenAuthentication(authentication.TokenAuthentication):
    """
     This is our custom token authenticator,
        so that we don't throw 401's for invalid user login
        instead we return None, and correctly populate our WsAuthResponse
    """
    def authenticate_credentials(self, key):
        try:
            token = Token.objects.select_related('user').get(key=key)
        except Token.DoesNotExist:
            return (None, '')

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        return (token.user, token)


class LogoutView(APIView):
    """
    API endpoint that allows a user to log out.
    """

    queryset = get_user_model().objects.all()
    authentication_classes = (WsTokenAuthentication,)

    def get(self, request, format=None):
        request.user.auth_token.delete()
        return Response(status=status.HTTP_200_OK)


class WsObtainAuthToken(BaseWsGenericAPIView):
    """
    post:
    Authenticate to Web Sight.
    """

    serializer_class = WsAuthTokenSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        response = WsAuthResponse(user, token)
        return Response(response.data)


class WsCheckAuthTokenStatus(APIView):
    """
    get:
    Get the authorization levels associated with an HTTP request's credentials.
    """

    permission_classes = [
        AllowAny
    ]
    authentication_classes = (WsTokenAuthentication,)

    def get(self, request, *args, **kwargs):
        user = request.user
        token = None
        if user.is_authenticated:
            token = Token.objects.filter(user=user).first()
        response = WsAuthResponse(user, token)
        return Response(response.data)

