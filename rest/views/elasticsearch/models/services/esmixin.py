# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..mixin import BaseEsMixin, BaseRelatedEsMixin


class SslSupportReportEsMixin(BaseEsMixin):
    """
    This is a mixin class for APIViews that query SSL support report models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_es_query_class(cls):
        from wselasticsearch.query import SslSupportReportQuery
        return SslSupportReportQuery

    # Public Methods

    # Protected Methods

    def _apply_aggregates_to_query(self, query):
        query.aggregate_on_term(key="cert_expired", name="cert_expired")
        query.aggregate_on_term(key="cert_is_valid", name="cert_is_valid")
        query.aggregate_on_term(key="cert_key_type", name="cert_key_type")
        query.aggregate_on_term(key="cert_key_bits", name="cert_key_bits")
        query.aggregate_on_term(key="cert_issuer_common_name", name="cert_issuer_common_name"),
        query.aggregate_on_term(key="cert_issuer_country", name="cert_issuer_country"),
        query.aggregate_on_term(key="cert_issuer_email", name="cert_issuer_email"),
        query.aggregate_on_term(key="cert_issuer_hash", name="cert_issuer_hash"),
        query.aggregate_on_term(key="cert_issuer_locality", name="cert_issuer_locality"),
        query.aggregate_on_term(key="cert_issuer_organization", name="cert_issuer_organization"),
        query.aggregate_on_term(key="cert_issuer_organizational_unit", name="cert_issuer_organizational_unit"),
        query.aggregate_on_term(key="cert_issuer_state", name="cert_issuer_state"),
        query.aggregate_on_term(key="cert_subject_common_name", name="cert_subject_common_name"),
        query.aggregate_on_term(key="cert_subject_country", name="cert_subject_country"),
        query.aggregate_on_term(key="cert_subject_email", name="cert_subject_email"),
        query.aggregate_on_term(key="cert_subject_hash", name="cert_subject_hash"),
        query.aggregate_on_term(key="cert_subject_locality", name="cert_subject_locality"),
        query.aggregate_on_term(key="cert_subject_organization", name="cert_subject_organization"),
        query.aggregate_on_term(key="cert_subject_organizational_unit", name="cert_subject_organizational_unit"),
        query.aggregate_on_term(key="cert_subject_state", name="cert_subject_state"),
        query.aggregate_on_term(key="network_service_port", name="network_service_port"),
        query.aggregate_on_term(key="network_cidr_range", name="network_cidr_range"),
        query.aggregate_on_term(key="is_vulnerable", name="is_vulnerable"),
        return query

    # Private Methods

    # Properties

    # Representation and Comparison


class LatestSslSupportReportEsMixin(SslSupportReportEsMixin):
    """
    This is a mixin class for APIViews that query SSL support report models that are members of the
    most recent scans for the SSL services on the investigated endpoints.
    """

    def _apply_filters_to_query(self, query):
        query = super(LatestSslSupportReportEsMixin, self)._apply_filters_to_query(query)
        query.filter_by_latest_scan()
        return query


class SslSupportRelatedEsMixin(BaseRelatedEsMixin):
    """
    This is a mixin class for APIViews that query data stored in models that inherit from SslSupportRelatedMixin.
    """

    @classmethod
    def get_es_query_class(cls):
        from wselasticsearch.query import SslSupportRelatedMultidocQuery
        return SslSupportRelatedMultidocQuery

    @classmethod
    def get_related_es_query_class(cls):
        from wselasticsearch.query import SslSupportReportQuery
        return SslSupportReportQuery

    @property
    def parent_related_value_key(self):
        return "cert_md5_digest"

    @property
    def related_filter_key(self):
        return "ssl_certificate_md5_digest"


class LatestSslSupportRelatedEsMixin(SslSupportRelatedEsMixin):
    """
    This is a mixin class for APIViews that query data stored in models that inherit from SslSupportRelatedMixin
    and are querying data base on the latest SslSupportReportModel associated with the relevant database
    object.
    """

    def _apply_filters_to_query(self, query):
        query = super(LatestSslSupportRelatedEsMixin, self)._apply_filters_to_query(query)
        query.filter_by_latest_scan()
        return query

    def _apply_related_elasticsearch_query_filters(self, query):
        query = super(LatestSslSupportRelatedEsMixin, self)._apply_related_elasticsearch_query_filters(query)
        query.filter_by_latest_scan()
        return query
