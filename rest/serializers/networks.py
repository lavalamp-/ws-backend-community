# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers
from rest_framework.validators import UniqueTogetherValidator

from rest.models import Network
from rest.models import Organization
from .base import WsBaseModelSerializer
from lib import RegexLib, ConfigManager, IPBlacklist

config = ConfigManager.instance()


class NetworkSerializer(WsBaseModelSerializer):
    """
    This is a serializer class for providing summary details about a network.
    """

    def validate(self, data):
        """
        Validate the contents of this NetworkSerializer to ensure that the network range
        is neither contained by nor contains any of the network ranges blacklisted by Web Sight.
        :param data: A dictionary containing the validated data associated with this object.
        :return: The validated data.
        """
        cidr_string = "%s/%s" % (data["address"], data["mask_length"])
        blacklist = IPBlacklist.instance()
        if blacklist.is_cidr_range_blacklisted(cidr_string):
            raise serializers.ValidationError(
                "That network range either contains or is contained by a network range that "
                "Web Sight does not support."
            )
        return data

    def validate_name(self, value):
        """
        Validate the contents of value for use as a Network name.
        :param value: The value to validate.
        :return: The value.
        """
        return value

    def validate_organization(self, value):
        """
        Validate the contents of value for use an an organization UUID.
        :param value: The value to validate.
        :return: The value
        """
        if self.requesting_user.is_superuser:
            return value
        else:
            if not value.can_user_write(self.requesting_user):
                raise serializers.ValidationError("We couldn't find that organization.")
            return value

    def validate_mask_length(self, value):
        """
        Validate the contents of mask_length for use as a network mask length.
        :param value: The value to validate.
        :return: The value
        """
        if value < config.rest_min_network_mask_length:
            raise serializers.ValidationError(
                "Smallest supported mask length is %s."
                % (config.rest_min_network_mask_length,)
            )
        if value > config.rest_max_network_mask_length:
            raise serializers.ValidationError(
                "Largest supported mask length is %s."
                % (config.rest_max_network_mask_length,)
            )
        return value

    def validate_address(self, value):
        """
        Validate the contents of of address for use as a network range address.
        :param value: The value to validate.
        :return: The value.
        """
        if not RegexLib.ipv4_address_regex.match(value):
            raise serializers.ValidationError("Not a valid IPv4 address.")
        return value

    class Meta:
        model = Network
        fields = (
            "uuid",
            "name",
            "address",
            "mask_length",
            "scanning_enabled",
            "organization",
            "endpoint_count",
            "cidr_range",
            "times_scanned",
            "last_scan_time",
            "created",
        )
        read_only_fields = ("uuid", "endpoint_count", "cidr_range", "times_scanned", "last_scan_time", "created")
        validators = [
            UniqueTogetherValidator(
                queryset=Network.objects.filter(added_by="user").all(),
                fields=("address", "mask_length", "organization"),
            ),
            UniqueTogetherValidator(
                queryset=Network.objects.all(),
                fields=("name", "organization"),
            ),
        ]
