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

    def filter_by_domain(self, domain_name):
        """
        Apply filters to restrict this query to only those results that have CNAME records that would cover
        the given domain name.
        :param domain_name: The domain name to query against.
        :return: None
        """
        if "." in domain_name:
            wild_domain = "*%s" % domain_name[domain_name.find("."):]
            self.or_by_term(key="cert_subject_common_name", value=wild_domain)
            self.or_by_term(key="cert_subject_common_name", value=domain_name)
        else:
            self.must_by_term(key="cert_subject_common_name", value=domain_name)
