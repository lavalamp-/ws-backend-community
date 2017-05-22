# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseManyArinRequest, BaseSingleArinRequest
from .network import NetworksArinRequest


class OrganizationArinRequest(BaseSingleArinRequest):
    """
    This is a request class for requesting information about a single organization.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_networks(cls, handle, *args, **kwargs):
        """
        Get a response containing the networks owned by the given organization.
        :param handle: The handle of the organization to retrieve networks for.
        :param args: Positional arguments to pass to requests.get.
        :param kwargs: Keyword arguments to pass to requests.get.
        :return: An ARIN response object wrapping the response returned by the ARIN WHOIS RWS API.
        """
        handle = "%s/nets" % (handle,)
        request_url = "%s/%s" % (cls.get_full_url(), handle)
        request = NetworksArinRequest()
        return request.send(request_url, *args, **kwargs)

    @classmethod
    def get_response_class(cls):
        from ..response import OrganizationArinResponse
        return OrganizationArinResponse

    @classmethod
    def get_url_path(cls):
        return "org"

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class OrganizationsArinRequest(BaseManyArinRequest):
    """
    This is a request class for requesting information about multiple organizations.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_response_class(cls):
        from ..response import OrganizationsArinResponse
        return OrganizationsArinResponse

    @classmethod
    def get_url_path(cls):
        return "orgs"

    @classmethod
    def search_by_name(cls, name, *args, **kwargs):
        """
        Perform a search for organizations that match the given name.
        :param name: The name to look for.
        :param args: Positional arguments to pass to requests.get.
        :param kwargs: Keyword arguments to pass to requests.get.
        :return: An ARIN response object wrapping the response returned by the ARIN WHOIS RWS API.
        """
        return cls.search_by_key(key="name", value=name, *args, **kwargs)

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
