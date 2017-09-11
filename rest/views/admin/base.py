# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework.permissions import IsAdminUser

from ..base import WsListAPIView, BaseWsGenericAPIView, WsListCreateAPIView


class BaseAdminWsListAPIView(WsListAPIView):
    """
    This is a base class for administrative REST list handlers that require admin access.
    """

    permission_classes = [IsAdminUser]


class BaseAdminWsGenericAPIView(BaseWsGenericAPIView):
    """
    This is a base class for administrative generic APIView REST handlers that require admin access.
    """

    permission_classes = [IsAdminUser]


class BaseAdminWsListCreateAPIView(WsListCreateAPIView):
    """
    This is a base class for administrative list/create APIView REST handlers.
    """

    permission_classes = [IsAdminUser]
