# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied

from .base import WsRetrieveUpdateDestroyAPIView, WsListAPIView
from rest.serializers import NetworkSerializer
from rest.models import Network


class NetworkQuerysetMixin(object):
    """
    This is a class that provides the queryset retrieval methods for querying network objects.
    """

    serializer_class = NetworkSerializer

    def _get_su_queryset(self):
        return Network.objects.all()

    def _get_user_queryset(self):
        return Network.objects\
            .filter(organization__auth_groups__users=self.request.user, organization__auth_groups__name="org_read")\
            .all()

    def perform_destroy(self, instance):
        if not self.request.user.is_superuser:
            self.__verify_write_permissions()
        return super(NetworkQuerysetMixin, self).perform_destroy(instance)

    def perform_update(self, serializer):
        if not self.request.user.is_superuser:
            self.__verify_write_permissions()
        return super(NetworkQuerysetMixin, self).perform_update(serializer)

    def __verify_write_permissions(self):
        """
        Verify that the requesting User has write permissions to the queried organization.
        :return: None
        """
        network = get_object_or_404(Network, pk=self.kwargs["pk"])
        if not network.organization.can_user_write(self.request.user):
            raise PermissionDenied("You do not have permission to modify that network.")


class NetworkDetailView(NetworkQuerysetMixin, WsRetrieveUpdateDestroyAPIView):
    """
    get:
    Get a specific network.

    delete:
    Delete a specific network.

    patch:
    Update a specific network.

    put:
    Update a specific network.
    """

    def perform_destroy(self, instance):
        network_uuid = unicode(instance.uuid)
        org_uuid = unicode(instance.organization.uuid)
        super(NetworkDetailView, self).perform_destroy(instance)
        from tasknode.tasks import handle_network_deletion
        handle_network_deletion.delay(network_uuid=network_uuid, org_uuid=org_uuid)


class NetworkListView(NetworkQuerysetMixin, WsListAPIView):
    """
    get:
    Get all networks.
    """
