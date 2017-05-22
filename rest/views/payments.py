# -*- coding: utf-8 -*-
from __future__ import absolute_import

import django_filters

from .base import WsListCreateAPIView, WsRetrieveDestroyAPIView
import rest.models
import rest.serializers
import rest.filters


class PaymentTokenListView(WsListCreateAPIView):
    """
    This is an APIView for listing and creating PaymentToken objects.
    """

    serializer_class = rest.serializers.PaymentTokenSerializer
    filter_backends = (django_filters.rest_framework.DjangoFilterBackend,)
    filter_class = rest.filters.PaymentTokenFilter
    ordering_fields = ("name", "can_be_charged")

    def _get_user_queryset(self):
        return self.request.user.payment_tokens.all()

    def _get_su_queryset(self):
        return rest.models.PaymentToken.objects.all()


class PaymentTokenDetailView(WsRetrieveDestroyAPIView):
    """
    This is an APIView for retrieving individual payment tokens as well as deleting them.
    """

    serializer_class = rest.serializers.PaymentTokenSerializer

    def _get_user_queryset(self):
        return self.request.user.payment_tokens.all()

    def _get_su_queryset(self):
        return rest.models.PaymentToken.objects.all()
