# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.db.models import Q
from rest_framework.decorators import api_view
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.generics import get_object_or_404

import rest.models
import rest.serializers
import rest.responses
from .base import WsListAPIView, WsRetrieveUpdateAPIView, WsListCreateChildAPIView, WsRetrieveUpdateDestroyAPIView


class ScanConfigQuerysetMixin(object):
    """
    This is a mixin class that provides queryset retrieval based on the privileges of
    the requesting user.
    """

    serializer_class = rest.serializers.ScanConfigSerializer

    def _get_user_queryset(self):
        return rest.models.ScanConfig.objects.filter(
            Q(user=self.request.user) |
            Q(is_default=True) |
            Q(organization__auth_groups__users=self.request.user, organization__auth_groups__name="org_read")
        ).all()

    def _get_su_queryset(self):
        return rest.models.ScanConfig.objects.all()


class ScanConfigListView(ScanConfigQuerysetMixin, WsListAPIView):
    """
    Get all scan configuration objects.
    """


class ScanConfigDetailView(ScanConfigQuerysetMixin, WsRetrieveUpdateDestroyAPIView):
    """
    get:
    Get a specific scan configuration object.
    """

    _scan_config = None

    def initial(self, request, *args, **kwargs):
        self._scan_config = None
        return super(ScanConfigDetailView, self).initial(request, *args, **kwargs)

    def perform_destroy(self, instance):
        if not self.scan_config.is_default:
            raise PermissionDenied()
        elif not self.request.user.is_superuser:
            raise PermissionDenied()
        else:
            return super(ScanConfigDetailView, self).perform_destroy(instance)

    def perform_update(self, serializer):
        if self.scan_config.is_default and not self.request.user.is_superuser:
            raise PermissionDenied()
        elif hasattr(self.scan_config, "organization") \
                and self.request.user not in self.scan_config.organization.admin_group.users.all() \
                and not self.request.user.is_superuser:
            raise PermissionDenied(
                "You do not have administrative permissions for the scanning configuration's organization."
            )
        elif not self.scan_config.can_be_modified:
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


class DefaultScanConfigListView(WsListAPIView):
    """
    This is a view for retrieving all of the default ScanConfig objects contained within the database.
    """

    pagination_enabled = False
    serializer_class = rest.serializers.ScanConfigSerializer

    def get_queryset(self):
        return rest.models.ScanConfig.objects.filter(is_default=True).all()


class BaseScanConfigListCreateChildAPIView(WsListCreateChildAPIView):
    """
    This is a base class for all views that intend to query or create children for a ScanConfig
    object.
    """

    def check_permissions(self, request):
        super(BaseScanConfigListCreateChildAPIView, self).check_permissions(request)
        if self.parent_object.is_default and not request.user.is_superuser:
            raise PermissionDenied()
        elif hasattr(self.parent_object, "organization"):
            if self.request.user not in self.parent_object.organization.admin_group.users.all() \
                    and not self.request.user.is_superuser:
                raise PermissionDenied(
                    "You do not have administrative permissions for the scanning configuration's organization."
                )
        elif (not self.parent_object.order or self.parent_object.order.user != request.user) \
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


class DnsRecordTypesByScanConfigView(BaseScanConfigListCreateChildAPIView):
    """
    get:
    Get all of the DnsRecordType models associated with a ScanConfig.

    post:
    Create a new DnsRecordType for the referenced ScanConfig.
    """

    serializer_class = rest.serializers.DnsRecordTypeRelatedSerializer
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

    serializer_class = rest.serializers.ScanPortRelatedSerializer
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
                    Q(user=request.user) | Q(is_default=True)
                )
        scan_config = query.get(pk=pk)
    except rest.models.ScanConfig.DoesNotExist:
        raise NotFound()
    return rest.responses.WsScanConfigValidityResponse(scan_config=scan_config, status=200)
