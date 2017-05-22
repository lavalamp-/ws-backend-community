# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import S3Helper
from ..mixin import BaseEsMixin


class WebScanFiltersMixin(object):
    """
    This class contains filter configuration for all web service scan-based Elasticsearch querying
    functionality.
    """

    @property
    def hard_filterable_fields(self):
        return [
            "network_service_port",
            "network_cidr_range",
            "web_service_uses_ssl",
        ]

    @property
    def soft_filterable_fields(self):
        return [
            "uses_wordpress",
            "uses_iis",
            "uses_apache",
            "uses_nginx",
            "uses_tomcat_management_portal",
        ]


class WebServiceReportEsMixin(BaseEsMixin):
    """
    This is a mixin class for APIViews that query web service report models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_es_query_class(cls):
        from wselasticsearch.query import WebServiceReportQuery
        return WebServiceReportQuery

    # Public Methods

    # Protected Methods

    def _apply_aggregates_to_query(self, query):
        query.aggregate_on_term(key="uses_wordpress")
        query.aggregate_on_term(key="uses_iis")
        query.aggregate_on_term(key="uses_apache")
        query.aggregate_on_term(key="uses_nginx")
        query.aggregate_on_term(key="uses_tomcat_management_portal")
        query.aggregate_on_term(key="network_cidr_range")
        query.aggregate_on_term(key="network_service_port")
        query.aggregate_on_term(key="web_service_uses_ssl")
        query.aggregate_on_term(key="has_www_authenticate_headers")
        query.aggregate_on_term(key="hostname_is_ip_address")
        return query

    def _get_object_from_result(self, es_result):
        to_return = super(WebServiceReportEsMixin, self)._get_object_from_result(es_result)
        s3_key = None
        s3_bucket = None
        has_screenshots = None
        if "main_screenshot_s3_key" in to_return:
            s3_key = to_return.pop("main_screenshot_s3_key")
        if "main_screenshot_s3_bucket" in to_return:
            s3_bucket = to_return.pop("main_screenshot_s3_bucket")
        if "has_screenshots" in to_return:
            has_screenshots = to_return["has_screenshots"]
        if has_screenshots and s3_key and s3_bucket:
            s3_helper = S3Helper.instance()
            to_return["screenshot_url"] = s3_helper.get_signed_url_for_key(
                key=s3_key,
                bucket=s3_bucket,
            )
        return to_return

    # Private Methods

    # Properties

    # Representation and Comparison


class LatestWebServiceReportEsMixin(WebServiceReportEsMixin):
    """
    This is a mixin class for APIViews that query web service report models that are members of the
    most recent scans associated with investigated endpoints.
    """

    def _apply_filters_to_query(self, query):
        query = super(LatestWebServiceReportEsMixin, self)._apply_filters_to_query(query)
        query.filter_by_latest_scan()
        return query


class WebResourceEsMixin(BaseEsMixin):
    """
    This is a mixin class for APIViews that query web service resource models.
    """

    @classmethod
    def get_es_query_class(cls):
        from wselasticsearch.query import WebResourceMultidocQuery
        return WebResourceMultidocQuery

    def _apply_aggregates_to_query(self, query):
        query.aggregate_on_term(key="content_type", name="content_type")
        query.aggregate_on_term(key="response_status", name="response_status")
        query.aggregate_on_term(key="has_login_form", name="has_login_form")
        query.aggregate_on_term(key="request_method", name="request_method")
        return query


class LatestWebResourceEsMixin(WebResourceEsMixin):
    """
    This is a mixin class for APIViews that query web service resource models that are members of
    the most recent scans associated with investigated endpoints.
    """

    def _apply_filters_to_query(self, query):
        query = super(LatestWebResourceEsMixin, self)._apply_filters_to_query(query)
        query.filter_by_latest_scan()
        return query


class WebTechnologiesReportEsMixin(WebScanFiltersMixin):
    """
    This is a mixin class for APIViews that query web service technology report models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_es_query_class(cls):
        from wselasticsearch.query import WebServiceTechnologiesReportQuery
        return WebServiceTechnologiesReportQuery

    # Public Methods

    # Protected Methods

    def _apply_aggregates_to_query(self, query):
        query.count_term(key="uses_wordpress", value=True, name="uses_wordpress")
        query.count_term(key="uses_iis", value=True, name="uses_iis")
        query.count_term(key="uses_apache", value=True, name="uses_apache")
        query.count_term(key="uses_nginx", value=True, name="uses_nginx")
        query.aggregate_on_term(key="network_cidr_range", name="network_ranges")
        query.aggregate_on_term(key="network_service_port", name="ports")
        query.aggregate_on_term(key="web_service_uses_ssl", name="ssl_support")
        return query

    # Private Methods

    # Properties

    @property
    def queried_fields(self):
        return [
            "uses_wordpress",
            "uses_iis",
            "uses_apache",
            "uses_nginx",
        ]

    # Representation and Comparison


class LatestWebTechnologiesReportEsMixin(WebTechnologiesReportEsMixin):
    """
    This is a mixin class for APIViews that query web service technology report models that are members
    of the most recent scans associated with investigated endpoints.
    """

    def _apply_filters_to_query(self, query):
        query = super(LatestWebTechnologiesReportEsMixin, self)._apply_filters_to_query(query)
        query.filter_by_latest_scan()
        return query


class WebHeadersReportEsMixin(WebScanFiltersMixin):
    """
    This is a mixin class for APIViews that query web service header report models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_es_query_class(cls):
        from wselasticsearch.query import WebServiceHeadersReportQuery
        return WebServiceHeadersReportQuery

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def queried_fields(self):
        return [
            "total_header_count",
            "unique_header_count",
            "server_headers",
        ]

    # Representation and Comparison


class LatestWebHeadersReportEsMixin(WebHeadersReportEsMixin):
    """
    This is a mixin class for APIViews that query web service header report models that are members
    of the most recent scan associated with investigated endpoints.
    """

    def _apply_filters_to_query(self, query):
        query = super(LatestWebHeadersReportEsMixin, self)._apply_filters_to_query(query)
        query.filter_by_latest_scan()
        return query


class HttpTransactionEsMixin(WebScanFiltersMixin):
    """
    This is a mixin class for APIViews that query HTTP transaction Elasticsearch models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_es_query_class(cls):
        from wselasticsearch.query import HttpTransactionQuery
        return HttpTransactionQuery

    # Public Methods

    # Protected Methods

    def _apply_aggregates_to_query(self, query):
        query.aggregate_on_term(key="content_type", name="content_types")
        query.aggregate_on_term(key="response_status", name="response_statuses")
        query.aggregate_with_histogram(
            key="content_length",
            name="content_lengths",
            interval=self._get_content_length_interval(),
        )
        return query

    def _get_content_length_interval(self):
        """
        Get the interval size to use for the content length histogram.
        :return: The interval size to use for the content length histogram.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    # Properties

    @property
    def queried_fields(self):
        return [
            "response_headers",
            "content_type",
            "content_length",
            "content_hash",
            "content_secondary_hash",
            "request_method",
            "response_status",
            "url",
        ]

    @property
    def sortable_fields(self):
        return [
            "url",
            "response_status",
            "content_type",
            "content_length",
            "content_hash",
        ]

    # Representation and Comparison


class LatestHttpTransactionEsMixin(HttpTransactionEsMixin):
    """
    This is a mixin class for APIViews that query HTTP transaction Elasticsearch models that are members
    of the most recent scan associated with investigated endpoints.
    """

    def _apply_filters_to_query(self, query):
        query = super(LatestHttpTransactionEsMixin, self)._apply_filters_to_query(query)
        query.filter_by_latest_scan()
        return query


class HttpScreenshotEsMixin(WebScanFiltersMixin):
    """
    This is a mixin class for APIViews that query HTTP screenshot Elasticsearch models.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_es_query_class(cls):
        from wselasticsearch.query import HttpScreenshotQuery
        return HttpScreenshotQuery

    # Public Methods

    # Protected Methods

    def _get_object_from_result(self, es_result):
        to_return = super(HttpScreenshotEsMixin, self)._get_object_from_result(es_result)
        s3_helper = S3Helper.instance()
        s3_key = to_return.pop("s3_key")
        s3_bucket = to_return.pop("s3_bucket")
        to_return["image_url"] = s3_helper.get_signed_url_for_key(
            key=s3_key,
            bucket=s3_bucket,
        )
        return to_return

    # Private Methods

    # Properties

    @property
    def queried_fields(self):
        return [
            "url",
            "s3_key",
            "s3_bucket",
            "web_service_uuid",
        ]

    @property
    def sortable_fields(self):
        return ["url"]

    # Representation and Comparison


class LatestHttpScreenshotEsMixin(HttpScreenshotEsMixin):
    """
    This is a mixin class for APIViews that query HTTP screenshot Elasticsearch models that are members
    of the most recent scan associated with investigated endpoints.
    """

    def _apply_filters_to_query(self, query):
        query = super(LatestHttpScreenshotEsMixin, self)._apply_filters_to_query(query)
        query.filter_by_latest_scan()
        return query
