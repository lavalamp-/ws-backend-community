# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.shortcuts import get_object_or_404
from rest_framework.exceptions import PermissionDenied

from .base import WsRetrieveUpdateDestroyAPIView, WsListAPIView
from rest.models import DomainName
from rest.serializers import DomainNameSerializer


class DomainNameQuerysetMixin(object):
    """
    This is a class that provides queryset retrieval methods for querying domain name objects.
    """

    serializer_class = DomainNameSerializer

    def _get_su_queryset(self):
        return DomainName.objects.all()

    def _get_user_queryset(self):
        return DomainName.objects\
            .filter(organization__auth_groups__users=self.request.user, organization__auth_groups__name="org_read")\
            .all()

    def perform_destroy(self, instance):
        if not self.request.user.is_superuser:
            self.__verify_write_permissions()
        return super(DomainNameQuerysetMixin, self).perform_destroy(instance)

    def perform_update(self, serializer):
        if not self.request.user.is_superuser:
            self.__verify_write_permissions()
        return super(DomainNameQuerysetMixin, self).perform_update(serializer)

    def __verify_write_permissions(self):
        """
        Verify that the requesting User has write permissions to the queried organization.
        :return: None
        """
        network = get_object_or_404(DomainName, pk=self.kwargs["pk"])
        if not network.organization.can_user_write(self.request.user):
            raise PermissionDenied("You do not have permission to modify that network.")


class DomainNameDetailView(DomainNameQuerysetMixin, WsRetrieveUpdateDestroyAPIView):
    """
    API endpoint for retrieving or manipulating data about a single domain name.
    """


class DomainNameListView(DomainNameQuerysetMixin, WsListAPIView):
    """
    API endpoint for retrieving all domain names.
    """
