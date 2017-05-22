# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers

from rest.models import NetworkService


class NetworkServiceSummarySerializer(serializers.HyperlinkedModelSerializer):
    """
    This is a serializer class for providing summary details about a network service.
    """

    class Meta:
        model = NetworkService
        fields = ("uuid", "port", "protocol", "is_monitored")
