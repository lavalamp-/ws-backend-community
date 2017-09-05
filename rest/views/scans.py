# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db.models import Q
from rest_framework.decorators import api_view
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.generics import get_object_or_404

import rest.models
import rest.serializers
import rest.responses
from .base import WsListAPIView, WsRetrieveUpdateAPIView, WsListCreateChildAPIView


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


class ScanConfigDetailView(ScanConfigQuerysetMixin, WsRetrieveUpdateAPIView):
    """
    get:
    Get a specific scan configuration object.
    """

    _scan_config = None

    def check_permissions(self, request):
        super(ScanConfigDetailView, self).check_permissions(request)
        if (not self.scan_config.order or self.scan_config.order.user != request.user) \
                and not request.user.is_superuser:
            raise NotFound()

    def initial(self, request, *args, **kwargs):
        self._scan_config = None
        return super(ScanConfigDetailView, self).initial(request, *args, **kwargs)

    def perform_update(self, serializer):
        if not self.scan_config.can_be_modified:
            raise PermissionDenied("That scan configuration cannot be modified.")
        else:
            return super(ScanConfigDetailView, self).perform_update(serializer)

    @property
    def scan_config(self):
        """
        Get the ScanConfig that this handler is referencing.
        :return: the ScanConfig that this handler is referencing.
        """
        if self._scan_config is None:
            self._scan_config = get_object_or_404(rest.models.ScanConfig, pk=self.kwargs["pk"])
        return self._scan_config


class BaseScanConfigListCreateChildAPIView(WsListCreateChildAPIView):
    """
    This is a base class for all views that intend to query or create children for a ScanConfig
    object.
    """

    def check_object_permissions(self, request, obj):
        super(BaseScanConfigListCreateChildAPIView, self).check_object_permissions(request, obj)
        if (not self.parent_object.order or self.parent_object.order.user != request.user) \
                and not request.user.is_superuser:
            raise NotFound()

    def perform_create(self, serializer):
        if not self.parent_object.can_be_modified:
            raise PermissionDenied("That scan configuration cannot be modified.")
        else:
            return super(BaseScanConfigListCreateChildAPIView, self).perform_create(serializer)

    @property
    def parent_class(self):
        return rest.models.ScanConfig


class DefaultScanConfigListView(WsListAPIView):
    """
    This is a view for retrieving all of the default ScanConfig objects contained within the database.
    """

    pagination_enabled = False
    serializer_class = rest.serializers.ScanConfigSerializer

    def get_queryset(self):
        return rest.models.ScanConfig.objects.filter(is_default=True).all()


class DnsRecordTypesByScanConfigView(BaseScanConfigListCreateChildAPIView):
    """
    get:
    Get all of the DnsRecordType models associated with a ScanConfig.

    post:
    Create a new DnsRecordType for the referenced ScanConfig.
    """

    serializer_class = rest.serializers.DnsRecordTypeSerializer
    ordering_fields = ("record_type",)

    def _get_parent_mapping(self):
        return {
            "scan_config": self.parent_object,
        }

    @property
    def relationship_key(self):
        return "scan_config_id"

    @property
    def child_attribute(self):
        return "dns_record_types"


class ScanPortsByScanConfigView(BaseScanConfigListCreateChildAPIView):
    """
    get:
    Get all of the ScanPort models associated with a ScanConfig.

    post:
    Create a new ScanPort for the referenced ScanConfig.
    """

    serializer_class = rest.serializers.ScanPortSerializer
    ordering_fields = ("port_number",)

    def _get_parent_mapping(self):
        return {
            "scan_config": self.parent_object,
        }

    @property
    def relationship_key(self):
        return "scan_config_id"

    @property
    def child_attribute(self):
        return "scan_ports"


@api_view(["GET"])
def check_scan_config_validity(request, pk=None):
    """
    Check to see if a given ScanConfig is valid for an order to be placed with
    it.
    :param request: The request that invoked this handler.
    :param pk: The primary key of the ScanConfig to check.
    :return: An HTTP response.
    """
    try:
        if request.user.is_superuser:
            query = rest.models.ScanConfig.objects
        else:
            query = rest.models.ScanConfig.objects\
                .filter(
                    Q(
                        order__organization__auth_groups__users=request.user,
                        order__organization__auth_groups__name="org_read",
                    ) | Q(is_default=True)
                )
        scan_config = query.get(pk=pk)
    except rest.models.ScanConfig.DoesNotExist:
        raise NotFound()
    return rest.responses.WsScanConfigValidityResponse(scan_config=scan_config, status=200)
