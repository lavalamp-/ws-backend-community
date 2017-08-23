# -*- coding: utf-8 -*-
from __future__ import absolute_import

import django.core.exceptions
from rest_framework import viewsets, generics, serializers, parsers
from rest_framework.generics import GenericAPIView
from rest_framework.views import APIView

from .mixin import ListChildMixin, ListCreateChildMixin, OwnershipFilterMixin, BaseAPIViewMixin, ListMixin, \
    WsRetrieveMixin, WsDestroyMixin, WsUpdateMixin


class BaseWsAPIView(BaseAPIViewMixin, APIView):
    """
    A base APIView class for all Web Sight APIView classes that do not follow the standard
    implementations of list, create, delete, etc.
    """


class BaseWsGenericAPIView(BaseAPIViewMixin, GenericAPIView):
    """
    A base GenericAPIView class for all Web Sight GenericAPIView classes.
    """


class WsListAPIView(OwnershipFilterMixin, ListMixin):
    """
    A base ListAPIView class for all Web Sight base REST ListAPIView handlers.
    """


class WsListCreateAPIView(OwnershipFilterMixin, ListMixin, generics.CreateAPIView):
    """
    A base ListCreateAPIView class for all Web Sight base REST ListCreateAPIView handlers.
    """


class WsListCreateChildAPIView(ListCreateChildMixin, generics.ListCreateAPIView):
    """
    A base CreateAPIView class for all Web Sight REST CreateAPIView handlers.
    """


class WsListChildAPIView(ListChildMixin, generics.ListAPIView):
    """
    A base APIView for all Web Sight REST handlers that list object children.
    """


class WsRetrieveDestroyAPIView(
    OwnershipFilterMixin,
    WsRetrieveMixin,
    WsDestroyMixin,
):
    """
    A base RetrieveDestroyAPIView class for all Web Sight REST RetrieveDestroyAPIView handlers.
    """


class WsRetrieveAPIView(OwnershipFilterMixin, WsRetrieveMixin):
    """
    A base RetrieveAPIView class for all Web Sight REST RetrieveAPIView handlers.
    """


class WsRetrieveUpdateDestroyAPIView(
    OwnershipFilterMixin,
    WsRetrieveMixin,
    WsUpdateMixin,
    WsDestroyMixin,
):
    """
    A base RetrieveUpdateDestroyAPIView class for all Web Sight REST RetrieveUpdateDestroyAPIView handlers.
    """


class WsRetrieveUpdateAPIView(
    OwnershipFilterMixin,
    WsRetrieveMixin,
    WsUpdateMixin,
):
    """
    A base RetrieveUpdateAPIView class for all Web Sight REST RetrieveUpdateAPIView handlers.
    """


class WsCreateAPIView(generics.CreateAPIView):
    """
    A base CreateAPIView class for all Web Sight REST CreateAPIView handlers.
    """
