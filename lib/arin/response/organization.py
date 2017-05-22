# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..models import ArinOrganizationSummary, ArinOrganizationDetail
from .base import BaseManyArinResponse, BaseSingleArinResponse


class OrganizationArinResponse(BaseSingleArinResponse):
    """
    Documentation for OrganizationArinResponse.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        super(OrganizationArinResponse, self).__init__(*args, **kwargs)
        self._organization = None

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def organization(self):
        """
        Get the organization that was returned in the wrapped response.
        :return: the organization that was returned in the wrapped response.
        """
        if self._organization is None:
            if self.has_content:
                self._organization = ArinOrganizationDetail(self.content["org"])
        return self._organization

    # Representation and Comparison


class OrganizationsArinResponse(BaseManyArinResponse):
    """
    This is a response class for handling data returned by the ARIN WHOIS API containing information about
    organizations.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        super(OrganizationsArinResponse, self).__init__(*args, **kwargs)
        self._organizations = None

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def organizations(self):
        """
        Get a list containing the organizations returned by the wrapped response.
        :return: a list containing the organizations returned by the wrapped response.
        """
        if self._organizations is None:
            if self.has_content:
                if isinstance(self.content["orgs"]["orgRef"], list):
                    self._organizations = [ArinOrganizationSummary(x) for x in self.content["orgs"]["orgRef"]]
                else:
                    self._organizations = [ArinOrganizationSummary(self.content["orgs"]["orgRef"])]
            else:
                self._organizations = []
        return self._organizations

    # Representation and Comparison


