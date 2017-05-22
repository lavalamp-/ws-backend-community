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


class WsObtainAuthToken(APIView):
    """
     This view is used to log in users, and create a new auth token for that user
    """
    throttle_classes = ()
    permission_classes = ()
    parser_classes = (parsers.FormParser, parsers.MultiPartParser, parsers.JSONParser,)
    renderer_classes = (renderers.JSONRenderer,)
    serializer_class = WsAuthTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(request, data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        response = WsAuthResponse(user, token)
        return Response(response.data)


class WsCheckAuthTokenStatus(APIView):
    """
     This view is called to check the status of an api token,
        WsTokenAuthentication will test if that token is currently valid
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

