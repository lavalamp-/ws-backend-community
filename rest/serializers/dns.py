# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework.validators import UniqueTogetherValidator
from rest_framework import serializers

from .base import WsBaseModelSerializer
from rest.models import DomainName, DnsRecordType
from lib import RegexLib, FileHelper


class DomainNameSerializer(WsBaseModelSerializer):
    """
    This is a serializer class for providing details about a network.
    """

    def validate_name(self, value):
        """
        Validate the contents of value for use as a domain name.
        :param value: A string representing the domain name to process.
        :return: The value.
        """
        if not RegexLib.domain_name_regex.match(value):
            raise serializers.ValidationError("Not a valid domain name.")
        return value

    def validate_organization(self, value):
        """
        Validate the contents of value for use as an Organization.
        :param value: The value to validate.
        :return: The value.
        """
        if self.requesting_user.is_superuser:
            return value
        else:
            if not value.can_user_write(self.requesting_user):
                raise serializers.ValidationError("We couldn't find that organization.")
            return value

    class Meta:
        model = DomainName
        fields = (
            "uuid",
            "name",
            "is_monitored",
            "scanning_enabled",
            "organization",
            "created",
            "times_scanned",
            "last_scan_time",
        )
        read_only_fields = ("uuid", "is_monitored", "created", "times_scanned", "last_scan_time")
        validators = [
            UniqueTogetherValidator(
                queryset=DomainName.objects.all(),
                fields=("name", "organization"),
            )
        ]


class DnsRecordTypeSerializer(WsBaseModelSerializer):
    """
    This is a serializer class for providing details about a DnsRecordType.
    """

    def validate_record_type(self, value):
        """
        Validate that the contents of value represnt a valid DNS record type supported by
        this Web Sight deployment.
        :param value: The value to validate.
        :return: The validated value.
        """
        valid_record_types = [x[0] for x in FileHelper.get_dns_record_types()]
        if value not in valid_record_types:
            raise serializers.ValidationError(
                "%s is not a supported DNS record type."
                % (value,)
            )
        return value

    class Meta:
        model = DnsRecordType
        fields = (
            "uuid",
            "created",
            "record_type",
            "scan_config",
        )
        read_only_fields = (
            "uuid",
            "created",
        )
        validators = [
            UniqueTogetherValidator(
                queryset=DnsRecordType.objects.all(),
                fields=("scan_config", "record_type"),
            ),
        ]
