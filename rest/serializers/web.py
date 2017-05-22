# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers
from rest.models import WebService, WebServiceScan


class WebServiceSummarySerializer(serializers.HyperlinkedModelSerializer):
    """
    This is a serializer class for providing summary details about a web service.
    """

    class Meta:
        model = WebService
        fields = ("uuid", "host_name", "ssl_enabled", "ip_address", "port")


class WebServiceDetailSerializer(serializers.HyperlinkedModelSerializer):
    """
    This is a serializer class for providing in-depth details about a web service.
    """

    class Meta:
        model = WebService
        fields = ("uuid", "host_name", "ssl_enabled", "ip_address", "port", "last_completed_scan_uuid")


class WebServiceScanDetailSerializer(serializers.HyperlinkedModelSerializer):
    """
    This is a serializer class for providing in-depth details about a web service scan.
    """

    web_service_uuid = serializers.ReadOnlyField(source="web_service__id")

    class Meta:
        model = WebServiceScan
        fields = ("uuid", "started_at", "ended_at", "web_service_uuid")
