# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.response import Response

from tasknode.tasks import initialize_scan_for_organization
from rest.models import Organization, ScanInvocation


@api_view(["PUT"])
def invoke_scan(request, pk=None):
    """
    This is a function-based view that kicks off a Web Sight scan for an organization.
    :param request: The request that invoked this handler.
    :param pk: The primary key of the organization to invoke a scan for.
    :return: A Django response.
    """
    organization = get_object_or_404(Organization, pk=pk)
    if not request.user.is_superuser:
        if not organization.can_user_scan(request.user):
            raise PermissionDenied("You do not have sufficient permissions to start scans for that organization.")
    if organization.monitored_networks_count == 0:
        raise ValidationError("You cannot start a scan for an organization that has no monitored networks.")
    elif organization.monitored_networks_size == 0:
        raise ValidationError(
            "There are zero endpoints within the monitored networks associated with that organization."
        )
    elif organization.available_scan_credits_count == 0:
        raise PermissionDenied(
            "There are currently no available scan credits for that organization. The next credit "
            "will be available at %s."
            % (organization.next_credit_available_time,)
        )
    invocation = ScanInvocation.objects.create()
    organization.scan_invocations.add(invocation)
    organization.save()
    initialize_scan_for_organization.delay(org_uuid=unicode(organization.uuid))
    return Response(status=204)
