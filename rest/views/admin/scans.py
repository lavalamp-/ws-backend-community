# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models
import rest.serializers
from .base import BaseAdminWsListCreateAPIView


class AdminDefaultScanConfigListCreateView(BaseAdminWsListCreateAPIView):
    """
    get:
    Get all of the default ScanConfig objects.

    post:
    Create a new default ScanConfig object.
    """

    serializer_class = rest.serializers.ScanConfigSerializer

    def get_queryset(self):
        return rest.models.ScanConfig.objects.filter(is_default=True).all()

    def perform_create(self, serializer):
        new_config = serializer.save()
        new_config.is_default = True
        new_config.save()
