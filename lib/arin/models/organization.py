# -*- coding: utf-8 -*-
from __future__ import absolute_import

from dateutil import parser

from .base import BaseArinDetailResourceModel, BaseArinSummaryResourceModel
from ..request import OrganizationArinRequest


class OrganizationMixin(object):
    """
    This is a mixin class for organization response objects.
    """

    def __init__(self, *args, **kwargs):
        super(OrganizationMixin, self).__init__(*args, **kwargs)
        self._nets = None

    @property
    def nets(self):
        """
        Get a list of the networks owned by this organization.
        :return: a list of the networks owned by this organization.
        """
        if self._nets is None:
            networks_response = OrganizationArinRequest.get_networks(self.handle)
            self._nets = networks_response.networks
        return self._nets


class ArinOrganizationDetail(OrganizationMixin, BaseArinDetailResourceModel):
    """
    This is a model class for representing detailed organization data returned by the ARIN WHOIS API.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        super(ArinOrganizationDetail, self).__init__(*args, **kwargs)
        self._registration_date = None
        self._update_date = None

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def city(self):
        """
        Get the city where this organization resides.
        :return: the city where this organization resides.
        """
        return self._get_attribute("city")

    @property
    def country(self):
        """
        Get the country code for where this organization resides.
        :return: the country code for where this organization resides.
        """
        return self.resource["iso3166-1"]["code2"]["$"]

    @property
    def full_address(self):
        """
        Get a string containing the full address of this organization.
        :return: a string containing the full address of this organization.
        """
        return "%s %s, %s %s (%s)" % (
            self.street_address,
            self.city,
            self.state,
            self.postal_code,
            self.country,
        )

    @property
    def postal_code(self):
        """
        Get the postal code where this organization resides.
        :return: the postal code where this organization resides.
        """
        return self._get_attribute("postalCode")

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
    def state(self):
        """
        Get the state code for the state where this organization resides.
        :return: the state code for the state where this organization resides.
        """
        return self._get_attribute("iso3166-2")

    @property
    def street_address(self):
        """
        Get the street address where this organization resides.
        :return: the street address where this organization resides.
        """
        line = self.resource["streetAddress"]["line"]
        if isinstance(line, list):
            to_return = []
            for cur_line in line:
                to_return.append(cur_line["$"].strip())
            return " ".join(to_return)
        else:
            return line["$"].strip()

    @property
    def update_date(self):
        """
        Get a datetime representing when this organization was last updated.
        :return: a datetime representing when this organization was last updated.
        """
        if self._update_date is None:
            self._update_date = parser.parse(self._get_attribute("updateDate"))
        return self._update_date

    # Representation and Comparison


class ArinOrganizationSummary(OrganizationMixin, BaseArinSummaryResourceModel):
    """
    This is a model class for representing summary organization data returned by the ARIN WHOIS API.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
