# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework.validators import UniqueTogetherValidator
from rest_framework import serializers

from .base import WsBaseModelSerializer
from rest.models import DomainName
from lib import RegexLib


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
