# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.http import JsonResponse


def custom404(request):
    """
    This is a custom 404 handler for handling HTTP 404 not found errors.
    :param request: The request that resulted in the 404 error being thrown.
    :return: A Django response.
    """
    return JsonResponse({
        "status_code": 404,
        "message": "Not found",
        "detail": "The resource that you requested was not found.",
        "error_fields": [],
    }, status=404)
