# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseNetworkServiceScanQuery


class SslSupportQuery(BaseNetworkServiceScanQuery):
    """
    This is an Elasticsearch model class for querying SslSupportModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import SslSupportModel
        return SslSupportModel

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class SslVulnerabilityQuery(BaseNetworkServiceScanQuery):
    """
    This is an Elasticsearch model class for querying SslVulnerabilityModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import SslVulnerabilityModel
        return SslVulnerabilityModel

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class SslVulnerabilitiesQuery(BaseNetworkServiceScanQuery):
    """
    This is an Elasticsearch model class for querying SslVulnerabilitiesModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import SslVulnerabilitiesModel
        return SslVulnerabilitiesModel

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class SslCertificateQuery(BaseNetworkServiceScanQuery):
    """
    This is an Elasticsearch model class for querying SslCertificateModel objects.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import SslCertificateModel
        return SslCertificateModel

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class SslSupportReportQuery(BaseNetworkServiceScanQuery):
    """
    This is an Elasticsearch query class for querying SslSupportReportModel objects.
    """

    @classmethod
    def get_queried_class(cls):
        from wselasticsearch.models import SslSupportReportModel
        return SslSupportReportModel
