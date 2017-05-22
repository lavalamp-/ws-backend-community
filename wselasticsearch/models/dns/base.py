# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..organizations.base import BaseOrganizationModel
from ..types import *


class BaseDomainNameModel(BaseOrganizationModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a given domain
    name.
    """

    # Class Members

    domain_uuid = KeywordElasticsearchType()
    domain_name = KeywordElasticsearchType()
    domain_added_by = KeywordElasticsearchType()

    # Instantiation

    def __init__(self, domain_uuid=None, domain_name=None, domain_added_by=None, **kwargs):
        super(BaseDomainNameModel, self).__init__(**kwargs)
        self.domain_uuid = domain_uuid
        self.domain_name = domain_name
        self.domain_added_by = domain_added_by

    # Static Methods

    # Class Methods

    @classmethod
    def get_has_mapped_parent(cls):
        return True

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import DomainName
        return DomainName

    @classmethod
    def get_mapped_model_parent(cls):
        return "organization"

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.domain_uuid = WsFaker.create_uuid()
        to_populate.domain_name = WsFaker.get_domain_name()
        to_populate.domain_added_by = WsFaker.get_word()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.domain_uuid = database_model.uuid
        to_populate.domain_name = database_model.name
        to_populate.domain_added_by = database_model.added_by
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s)>" % (self.__class__.__name__, self.domain_name, self.domain_uuid)


class BaseDomainNameScanModel(BaseDomainNameModel):
    """
    This is a base Elasticsearch model for representing data that is tied to a given domain name
    scan.
    """

    # Class Members

    domain_scan_uuid = KeywordElasticsearchType()
    is_latest_scan = BooleanElasticsearchType()

    # Instantiation

    def __init__(self, domain_scan_uuid=None, is_latest_scan=None, **kwargs):
        super(BaseDomainNameScanModel, self).__init__(**kwargs)
        self.domain_scan_uuid = domain_scan_uuid
        self.is_latest_scan = is_latest_scan

    # Static Methods

    # Class Methods

    @classmethod
    def get_has_mapped_parent(cls):
        return True

    @classmethod
    def get_mapped_model_class(cls):
        from lib.sqlalchemy import DomainNameScan
        return DomainNameScan

    @classmethod
    def get_mapped_model_parent(cls):
        return "domain_name"

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.domain_scan_uuid = WsFaker.create_uuid()
        to_populate.is_latest_scan = RandomHelper.flip_coin()
        return to_populate

    @classmethod
    def _populate_from_database_model(cls, database_model=None, to_populate=None):
        to_populate.domain_scan_uuid = database_model.uuid
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.domain_scan_uuid)
