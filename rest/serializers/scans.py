# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework import serializers

from .base import WsBaseModelSerializer
from .dns import DnsRecordTypeSerializer
from .organizations import ScanPortSerializer
import rest.models
from lib import RegexLib


class ScanConfigSerializer(WsBaseModelSerializer):
    """
    This is a serializer class for the ScanConfig rest model.
    """

    order = serializers.PrimaryKeyRelatedField(read_only=True)
    organization = serializers.PrimaryKeyRelatedField(read_only=True)
    user = serializers.PrimaryKeyRelatedField(read_only=True)

    def validate_network_scan_bandwidth(self, value):
        """
        Validate the contents of value are valid for use as a network scanning bandwidth.
        :param value: The value to validate.
        :return: The value if validation is passed.
        """
        if not RegexLib.zmap_bandwidth_regex.match(value):
            raise serializers.ValidationError(
                "The network scan bandwidth must be an integer followed by a bytes-per-second notation "
                "(ex: 100K, 10M, 1G)."
            )
        return value

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
            "organization",
            "user",
            "completion_web_hook_url",
            "completion_email_org_users",
            "completion_email_order_user",
        )
        read_only_fields = (
            "is_default",
            "uuid",
            "created",
        )


class ScanConfigChildrenSerializer(ScanConfigSerializer):
    """
    This is a serializer class for the ScanConfig rest model that includes the ScanConfig children.
    """

    dns_record_types = DnsRecordTypeSerializer(required=True, many=True)
    scan_ports = ScanPortSerializer(required=True, many=True)

    def create(self, validated_data):
        scan_ports_data = validated_data.pop("scan_ports")
        dns_record_types_data = validated_data.pop("dns_record_types")
        scan_config = rest.models.ScanConfig.objects.create(
            include_default_dns_record_types=False,
            include_default_scan_ports=False,
            **validated_data
        )
        for scan_port_data in scan_ports_data:
            rest.models.ScanPort.objects.create(scan_config=scan_config, **scan_port_data)
        for dns_record_type_data in dns_record_types_data:
            rest.models.DnsRecordType.objects.create(scan_config=scan_config, **dns_record_type_data)
        return scan_config

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
            "uuid",
            "is_default",
            "created",
            "completion_web_hook_url",
            "completion_email_org_users",
            "completion_email_order_user",
            "dns_record_types",
            "scan_ports",
        )
        read_only_fields = (
            "is_default",
            "uuid",
            "created",
            "order",
            "user",
            "organization",
        )


class OrganizationQuickScanSerializer(serializers.Serializer):
    """
    This is a serializer for the request body to the quick_scan_organization API handler.
    """

    scan_config_uuid = serializers.UUIDField(required=False, allow_null=True)
    scan_config = ScanConfigChildrenSerializer(required=False, many=False, allow_null=True)
    targets = serializers.ListField(child=serializers.CharField(), required=True)
    completion_web_hook_url = serializers.URLField(required=False)
    completion_email_org_users = serializers.BooleanField(required=False)
    completion_email_order_user = serializers.BooleanField(required=False)

    class Meta:
        fields = (
            "scan_config_uuid",
            "scan_config",
            "targets",
            "completion_web_hook_url",
            "completion_email_org_users",
            "completion_email_order_user",
        )

