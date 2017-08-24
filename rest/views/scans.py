# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models
import rest.serializers
from .base import WsListAPIView, WsRetrieveAPIView


class ScanConfigQuerysetMixin(object):
    """
    This is a mixin class that provides queryset retrieval based on the privileges of
    the requesting user.
    """

    serializer_class = rest.serializers.ScanConfigSerializer

    def _get_user_queryset(self):
        return self.request.user.scan_configs.all()

    def _get_su_queryset(self):
        return rest.models.ScanConfig.objects.all()


class ScanConfigListView(ScanConfigQuerysetMixin, WsListAPIView):
    """
    Get all scan configuration objects.
    """


class ScanConfigDetailView(ScanConfigQuerysetMixin, WsRetrieveAPIView):
    """
    get:
    Get a specific scan configuration object.
    """