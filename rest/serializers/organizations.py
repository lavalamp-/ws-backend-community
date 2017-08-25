# -*- coding: utf-8 -*-
from __future__ import absolute_import
from rest_framework import serializers
from csv import reader, DictReader

from rest_framework.validators import UniqueTogetherValidator

from rest.models import Organization, DomainName, Network, ScanPort
from rest.lib.exception import WsRestNonFieldException
from django.db import IntegrityError
from .base import WsBaseModelSerializer


class OrganizationSerializer(WsBaseModelSerializer):
    """
    This is a serializer class for providing in-depth details about an organization.
    """

    def validate_name(self, value):
        """
        Validate that the contents of value are valid for use as an organization name.
        :param value: The value to validate.
        :return: The value.
        """
        if not value:
            raise serializers.ValidationError("Organization names must not be empty.")
        return value

    class Meta:
        model = Organization
        fields = (
            "created",
            "uuid",
            "name",
            "description",
            "scanning_status",
            "network_service_count",
            "monitored_networks_count",
            "monitored_networks_size",
            "ready_for_scan",
            "last_scan_time",
            "networks_count",
            "networks_size",
            "domains_count",
            "monitored_domains_count",
        )
        read_only_fields = (
            "created",
            "uuid",
            "scanning_status",
            "network_service_count",
            "monitored_networks_count",
            "monitored_networks_size",
            "ready_for_scan",
            "last_scan_time",
            "networks_count",
            "networks_size",
            "domains_count",
            "monitored_domains_count",
        )


class OrganizationNetworkUploadRangeSerializer(serializers.Serializer):
    """
    This serializer handles files uploaded to add network ranges to an organization
    """

    def __init__(self, range_file, organization_uuid, data, **kwargs):
        self.range_file = range_file
        self.organization_uuid = organization_uuid
        super(OrganizationNetworkUploadRangeSerializer, self).__init__(self, data, **kwargs)

    def validate(self, attrs):

        if not self.organization_uuid:
            raise WsRestNonFieldException('No Organization uuid supplied.')

        if not self.range_file or not self.range_file.name.endswith('.csv'):
            raise WsRestNonFieldException('Supported file types for uploading network ranges are: csv')

        organization = Organization.objects.filter(uuid=self.organization_uuid).first()

        if organization:
            try:
                #For every row in the file, attempt to add the network
                for network_row in DictReader(self.range_file):
                    name = network_row['name']
                    address = network_row['address']
                    mask = int(network_row['mask'])
                    new_network = Network (
                        name = name,
                        address = address,
                        mask_length = mask,
                        organization = organization
                    )
                    new_network.save()

            except IntegrityError as ie:
                raise WsRestNonFieldException('Uploaded file contains a network range that already exists.')
            except Exception as e:
                raise WsRestNonFieldException(e.message)
        else:
            raise WsRestNonFieldException('No Organization with that uuid found.')

        return attrs


class OrganizationDomainNameUploadRangeSerializer(serializers.Serializer):
    """
        This serializer handles files uploaded to add domain names to an organization
    """

    def __init__(self, domain_file, organization_uuid, data, **kwargs):
        self.domain_file = domain_file
        self.organization_uuid = organization_uuid
        super(OrganizationDomainNameUploadRangeSerializer, self).__init__(self, data, **kwargs)

    def validate(self, attrs):

        if not self.organization_uuid:
            raise WsRestNonFieldException('No Organization uuid supplied.')

        if not self.domain_file or not self.domain_file.name.endswith('.csv'):
            raise WsRestNonFieldException('Supported file types for uploading domain name are: csv')

        organization = Organization.objects.filter(uuid=self.organization_uuid).first()

        if organization:
            try:
                #For every row in the file, attempt to add the network
                for network_row in DictReader(self.domain_file):
                    name = network_row['domain']

                    domainName = DomainName (
                        name = name,
                        organization = organization
                    )
                    domainName.save()

            except IntegrityError as ie:
                raise WsRestNonFieldException('Uploaded file contains a domain name that already exists.')
            except Exception as e:
                raise WsRestNonFieldException(e.message)
        else:
            raise WsRestNonFieldException('No Organization with that uuid found.')

        return attrs


class ScanPortSerializer(WsBaseModelSerializer):
    """
    This is a serializer class for serializing data related to ScanPort models.
    """

    class Meta:
        model = ScanPort
        fields = (
            "port_number",
            "protocol",
            "added_by",
            "included",
            "created",
            "uuid",
            "scan_config",
            "organization",
        )
        read_only_fields = (
            "added_by",
            "included",
            "created",
            "uuid",
        )
        validators = [
            UniqueTogetherValidator(
                queryset=ScanPort.objects.all(),
                fields=("scan_config", "port_number", "protocol"),
            )
        ]
