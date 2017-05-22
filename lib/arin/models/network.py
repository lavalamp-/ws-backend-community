# -*- coding: utf-8 -*-
from __future__ import absolute_import

from netaddr import IPRange
from dateutil import parser

from .base import BaseArinDetailResourceModel, BaseArinSummaryResourceModel
from ..request import OrganizationArinRequest
from lib import ElasticsearchableMixin


class NetworkMixin(object):
    """
    This is a mixin class for network response objects.
    """


class ArinNetworkDetail(NetworkMixin, BaseArinDetailResourceModel, ElasticsearchableMixin):
    """
    This is a model class for representing detailed network data returned by the ARIN WHOIS API.
    """

    def __init__(self, *args, **kwargs):
        super(ArinNetworkDetail, self).__init__(*args, **kwargs)
        self._organization = None
        self._registration_date = None
        self._update_date = None

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import IpWhoisModel
        return IpWhoisModel

    def _to_es_model(self):
        from wselasticsearch.models import IpWhoisModel
        return IpWhoisModel(
            whois_org_name=self.org_name,
            whois_org_handle=self.org_handle,
            whois_org_postal_code=self.org_postal_code,
            whois_org_country_code=self.org_country_code,
            whois_org_street_address=self.org_street_address,
            whois_org_city=self.org_city,
            whois_org_state=self.org_state,
            whois_org_registration_date=self.org_registration_date,
            whois_org_update_date=self.org_update_date,
            whois_network_handle=self.handle,
            whois_network_name=self.name,
            whois_network_range={
                "network_address": self.start_address,
                "mask_length": self.cidr_length,
            },
            whois_network_registration_date=self.registration_date,
            whois_network_update_date=self.update_date,
            whois_network_version=self.version,
        )

    @property
    def cidr_length(self):
        """
        Get the CIDR mask length for this network.
        :return: the CIDR mask length for this network.
        """
        return self.resource["netBlocks"]["netBlock"]["cidrLength"]["$"]

    @property
    def cidr_ranges(self):
        """
        Get a list of CIDR ranges that comprise all of the network space found in this range.
        :return: a list of CIDR ranges that comprise all of the network space found in this range.
        """
        return self.network_range.cidrs()

    @property
    def end_address(self):
        """
        Get the IP address where this network range ends.
        :return: the IP address where this network range ends.
        """
        return self._get_attribute("endAddress")

    @property
    def network_range(self):
        """
        Get the network range that this Network entry reflects.
        :return: the network range that this Network entry reflects.
        """
        return IPRange(self.start_address, self.end_address)

    @property
    def organization(self):
        """
        Get the organization that owns this network.
        :return: the organization that owns this network.
        """
        if self._organization is None:
            request = OrganizationArinRequest()
            organization_response = request.send(self.org_ref)
            self._organization = organization_response.organization
        return self._organization

    @property
    def org_city(self):
        """
        Get the city where the organization that owns this network resides.
        :return: the city where the organization that owns this network resides.
        """
        return self.organization.city

    @property
    def org_country_code(self):
        """
        Get the country code of the organization that owns this network.
        :return: the country code of the organization that owns this network.
        """
        return self.organization.country

    @property
    def org_handle(self):
        """
        Get the handle of the organization that owns this network.
        :return: the handle of the organization that owns this network.
        """
        return self.organization.handle

    @property
    def org_name(self):
        """
        Get the name of the organization that owns this network.
        :return: the name of the organization that owns this network.
        """
        return self.organization.name

    @property
    def org_postal_code(self):
        """
        Get the postal code of the organization that owns this network.
        :return: the postal code of the organization that owns this network.
        """
        return self.organization.postal_code

    @property
    def org_ref(self):
        """
        Get the URL that points to the owning organization for this netowrk.
        :return: the URL that points to the owning organization for this netowrk.
        """
        return self._get_attribute("orgRef")

    @property
    def org_registration_date(self):
        """
        Get the date on which the organization that owns this network was registered.
        :return: the date on which the organization that owns this network was registered.
        """
        return self.organization.registration_date

    @property
    def org_state(self):
        """
        Get the state where the organization that owns this network resides.
        :return: the state where the organization that owns this network resides.
        """
        return self.organization.state

    @property
    def org_street_address(self):
        """
        Get the street address of the organization that owns this network.
        :return: the street address of the organization that owns this network.
        """
        return self.organization.street_address

    @property
    def org_update_date(self):
        """
        Get the date on which the organization that owns this network was last updated.
        :return: the date on which the organization that owns this network was last updated.
        """
        return self.organization.update_date

    @property
    def registration_date(self):
        """
        Get a datetime representing when this organization was registered.
        :return: a datetime representing when this organization was registered.
        """
        if self._registration_date is None:
            self._registration_date = parser.parse(self._get_attribute("registrationDate"))
        return self._registration_date

    @property
    def start_address(self):
        """
        Get the IP address where this network range starts.
        :return: the IP address where this network range starts.
        """
        return self._get_attribute("startAddress")

    @property
    def update_date(self):
        """
        Get a datetime representing when this organization was last updated.
        :return: a datetime representing when this organization was last updated.
        """
        if self._update_date is None:
            self._update_date = parser.parse(self._get_attribute("updateDate"))
        return self._update_date

    @property
    def version(self):
        """
        Get the version associated with this network.
        :return: the version associated with this network.
        """
        return self._get_attribute("version")


class ArinNetworkSummary(NetworkMixin, BaseArinSummaryResourceModel):
    """
    This is a model class for representing summary network data returned by the ARIN WHOIS API.
    """

    @property
    def cidr_ranges(self):
        """
        Get a list of CIDR ranges that comprise all of the network space found in this range.
        :return: a list of CIDR ranges that comprise all of the network space found in this range.
        """
        return self.network_range.cidrs()

    @property
    def end_address(self):
        """
        Get the IP address where this network range ends.
        :return: the IP address where this network range ends.
        """
        return self._get_attribute("@endAddress")

    @property
    def network_range(self):
        """
        Get the network range that this Network entry reflects.
        :return: the network range that this Network entry reflects.
        """
        return IPRange(self.start_address, self.end_address)

    @property
    def start_address(self):
        """
        Get the IP address where this network range starts.
        :return: the IP address where this network range starts.
        """
        return self._get_attribute("@startAddress")
