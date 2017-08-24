# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers

from .base import WsBaseModelSerializer
import rest.models


class ScanConfigSerializer(WsBaseModelSerializer):
    """
    This is a serializer class for the ScanConfig rest model.
    """

    order = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = rest.models.ScanConfig
        fields = (
            "name",
            "description",
            "saved_for_later",
            "scan_domain_names",
            "scan_network_ranges",
            "scan_ip_addresses",
            "scan_network_services",
            "scan_ssl_support",
            "dns_enumerate_subdomains",
            "dns_scan_resolutions",
            "network_scan_bandwidth",
            "network_inspect_live_hosts",
            "ip_address_geolocate",
            "ip_address_reverse_hostname",
            "ip_address_historic_dns",
            "ip_address_as_data",
            "ip_address_whois_data",
            "network_service_check_liveness",
            "network_service_fingerprint",
            "network_service_inspect_app",
            "ssl_enumerate_vulns",
            "ssl_enumerate_cipher_suites",
            "ssl_retrieve_cert",
            "app_inspect_web_app",
            "web_app_include_http_on_https",
            "web_app_enum_vhosts",
            "web_app_take_screenshot",
            "web_app_do_crawling",
            "web_app_enum_user_agents",
            "order",
            "uuid",
            "is_default",
            "created",
        )
        read_only_fields = (
            "is_default",
            "uuid",
            "created",
        )
