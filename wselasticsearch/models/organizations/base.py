# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseMappedElasticsearchModel
from ..types import KeywordElasticsearchType


class BaseOrganizationModel(BaseMappedElasticsearchModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a given organization.
    """

    # Class Members

    org_uuid = KeywordElasticsearchType(
        help_text="The UUID of the organization that the data in this model is related to.",
    )

    # Instantiation

    def __init__(self, org_uuid=None, **kwargs):
        super(BaseOrganizationModel, self).__init__(**kwargs)
        self.org_uuid = org_uuid

    # Static Methods

    # Class Methods

    @classmethod
    def get_can_populate_dummy(cls):
        return True

    @classmethod
    def get_has_mapped_parent(cls):
        return False

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import Organization
        return Organization

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.org_uuid = WsFaker.create_uuid()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.org_uuid = database_model.uuid
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.org_uuid)


class BaseOrganizationNetworkScanModel(BaseOrganizationModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a given organization
    network scan.
    """

    # Class Members

    org_network_scan_uuid = KeywordElasticsearchType(
        help_text="The UUID of the network scan that the data in this model is related to.",
    )

    # Instantiation

    def __init__(self, network_scan_uuid=None, **kwargs):
        super(BaseOrganizationNetworkScanModel, self).__init__(**kwargs)
        self.org_network_scan_uuid = network_scan_uuid

    # Static Methods

    # Class Methods

    @classmethod
    def get_has_mapped_parent(cls):
        return True

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import OrganizationNetworkScan
        return OrganizationNetworkScan

    @classmethod
    def get_mapped_model_parent(cls):
        return "organization"

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.org_network_scan_uuid = WsFaker.create_uuid()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.org_network_scan_uuid = database_model.uuid
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.org_network_scan_uuid)
