# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseManyArinResponse, BaseSingleArinResponse
from ..models import ArinNetworkSummary, ArinNetworkDetail


class NetworkArinResponse(BaseSingleArinResponse):
    """
    This is a response class for handling data returned by the ARIN WHOIS API containing information
    about a single network.
    """

    def __init__(self, *args, **kwargs):
        super(NetworkArinResponse, self).__init__(*args, **kwargs)
        self._network = None

    @property
    def network(self):
        """
        Get the network contained by the wrapped response.
        :return: the network contained by the wrapped response.
        """
        if self._network is None:
            if self.has_content:
                self._network = ArinNetworkDetail(self.content["net"])
        return self._network


class NetworksArinResponse(BaseManyArinResponse):
    """
    This is a response class for handling data returned by the ARIN WHOIS API containing information
    about networks.
    """

    def __init__(self, *args, **kwargs):
        super(NetworksArinResponse, self).__init__(*args, **kwargs)
        self._networks = None

    @property
    def networks(self):
        """
        Get a list containing the networks returned by the wrapped response.
        :return: a list containing the networks returned by the wrapped response.
        """
        if self._networks is None:
            if self.has_content:
                if isinstance(self.content["nets"]["netRef"], list):
                    self._networks = [ArinNetworkSummary(x) for x in self.content["nets"]["netRef"]]
                else:
                    self._networks = [ArinNetworkSummary(self.content["nets"]["netRef"])]
            else:
                self._networks = []
        return self._networks
