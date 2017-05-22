# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseMultidocQuery


class SslSupportRelatedMultidocQuery(BaseMultidocQuery):
    """
    A query class for retrieving information about documents that are related to an SSL support report.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_queried_classes(cls):
        from lib import WsIntrospectionHelper
        return [x[1] for x in WsIntrospectionHelper.get_ssl_support_related_query_classes()]

    # Public Methods

    def filter_by_cert_md5_fingerprint(self, md5_fingerprint):
        """
        Apply a filter to this query to restrict results to only those results that contain the given
        certificate MD5 fingerprint.
        :param md5_fingerprint: The certificate MD5 fingerprint to filter against.
        :return: None
        """
        self.must_by_term(key="ssl_certificate_md5_digest", value=md5_fingerprint)

    def filter_by_latest_scan(self):
        """
        Apply a filter to this query to restrict results to only those results that were collected during
        most recent scans.
        :return: None
        """
        self.must_by_term(key="is_latest_scan", value=True)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
