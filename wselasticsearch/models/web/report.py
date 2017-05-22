# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebServiceScanModel
from ..types import *
from ..mixin import SslSupportRelatedMixin
from lib import DatetimeHelper


class WebServiceReportModel(BaseWebServiceScanModel, SslSupportRelatedMixin):
    """
    This is an Elasticsearch model class for containing aggregated and analyzed data about
    a web service as gathered from a single web service scan.
    """

    # Class Members

    uses_wordpress = BooleanElasticsearchType()
    uses_iis = BooleanElasticsearchType()
    uses_apache = BooleanElasticsearchType()
    uses_nginx = BooleanElasticsearchType()
    total_header_count = IntElasticsearchType()
    unique_header_count = IntElasticsearchType()
    server_headers = KeywordElasticsearchType()
    transactions_count = IntElasticsearchType()
    ok_count = IntElasticsearchType()
    has_ok = BooleanElasticsearchType()
    redirect_count = IntElasticsearchType()
    has_redirect = BooleanElasticsearchType()
    client_error_count = IntElasticsearchType()
    has_client_error = BooleanElasticsearchType()
    server_error_count = IntElasticsearchType()
    has_server_error = BooleanElasticsearchType()
    total_resource_size = IntElasticsearchType()
    uses_tomcat_management_portal = BooleanElasticsearchType()
    has_screenshots = BooleanElasticsearchType()
    screenshots_count = IntElasticsearchType()
    main_screenshot_s3_bucket = KeywordElasticsearchType()
    main_screenshot_s3_key = KeywordElasticsearchType()
    response_count = IntElasticsearchType()
    redirect_301_count = IntElasticsearchType()
    redirect_302_count = IntElasticsearchType()
    all_responses_redirects = BooleanElasticsearchType()
    all_responses_server_errors = BooleanElasticsearchType()
    all_responses_client_errors = BooleanElasticsearchType()
    response_statuses = CountDataPointElasticsearchType()
    hostname_resolves = BooleanElasticsearchType()
    resolved_ip_matches_hostname = BooleanElasticsearchType()
    response_content_types = CountDataPointElasticsearchType()
    www_authenticate_headers = KeywordElasticsearchType()
    has_www_authenticate_headers = BooleanElasticsearchType()
    has_basic_auth = BooleanElasticsearchType()
    has_digest_auth = BooleanElasticsearchType()
    has_ntlm_auth = BooleanElasticsearchType()
    basic_auth_realms = KeywordElasticsearchType()
    has_server_headers = BooleanElasticsearchType()
    has_multiple_server_headers = BooleanElasticsearchType()
    all_responses_not_found = BooleanElasticsearchType()
    resolved_ip_address = KeywordElasticsearchType()
    scan_completed_at = DateElasticsearchType()
    hostname_is_ip_address = BooleanElasticsearchType()
    open_ports = KeywordIntKeyValueElasticsearchType(key_name="protocol", value_name="port")
    landing_header_redirect_location = KeywordElasticsearchType()
    landing_meta_refresh_location = KeywordElasticsearchType()
    landing_response_status = IntElasticsearchType()
    landing_title = KeywordElasticsearchType()
    local_login_form_count = IntElasticsearchType()
    local_login_form_https_count = IntElasticsearchType()
    remote_login_form_count = IntElasticsearchType()
    remote_login_form_https_count = IntElasticsearchType()
    user_agent_fingerprints = UserAgentFingerprintElasticsearchType()

    # Instantiation

    def __init__(
            self,
            uses_wordpress=None,
            uses_iis=None,
            uses_apache=None,
            uses_nginx=None,
            total_header_count=None,
            unique_header_count=None,
            server_headers=None,
            transactions_count=None,
            ok_count=None,
            has_ok=None,
            redirect_count=None,
            has_redirect=None,
            client_error_count=None,
            has_client_error=None,
            server_error_count=None,
            has_server_error=None,
            total_resource_size=None,
            uses_tomcat_management_portal=None,
            has_screenshots=None,
            screenshots_count=None,
            main_screenshot_s3_bucket=None,
            main_screenshot_s3_key=None,
            response_count=None,
            redirect_301_count=None,
            redirect_302_count=None,
            all_responses_redirects=None,
            all_responses_server_errors=None,
            all_responses_client_errors=None,
            response_statuses=None,
            hostname_resolves=None,
            resolved_ip_matches_hostname=None,
            response_content_types=None,
            www_authenticate_headers=None,
            has_www_authenticate_headers=None,
            has_basic_auth=None,
            has_digest_auth=None,
            has_ntlm_auth=None,
            basic_auth_realms=None,
            has_server_headers=None,
            has_multiple_server_headers=None,
            all_responses_not_found=None,
            resolved_ip_address=None,
            ssl_certificate_cname=None,
            ssl_certificate_expired=None,
            ssl_certificate_is_valid=None,
            ssl_certificate_start_time=None,
            ssl_certificate_invalid_time=None,
            scan_completed_at=None,
            hostname_is_ip_address=None,
            has_ssl_certificate_data=None,
            ssl_certificate_md5_digest=None,
            open_ports=None,
            landing_header_redirect_location=None,
            landing_meta_refresh_location=None,
            landing_response_status=None,
            landing_title=None,
            local_login_form_count=None,
            local_login_form_https_count=None,
            remote_login_form_count=None,
            remote_login_form_https_count=None,
            user_agent_fingerprints=None,
            **kwargs
    ):
        super(WebServiceReportModel, self).__init__(**kwargs)
        self.uses_wordpress = uses_wordpress
        self.uses_iis = uses_iis
        self.uses_apache = uses_apache
        self.uses_nginx = uses_nginx
        self.total_header_count = total_header_count
        self.unique_header_count = unique_header_count
        self.server_headers = server_headers
        self.transactions_count = transactions_count
        self.ok_count = ok_count
        self.has_ok = has_ok
        self.redirect_count = redirect_count
        self.has_redirect = has_redirect
        self.client_error_count = client_error_count
        self.has_client_error = has_client_error
        self.server_error_count = server_error_count
        self.has_server_error = has_server_error
        self.total_resource_size = total_resource_size
        self.uses_tomcat_management_portal = uses_tomcat_management_portal
        self.has_screenshots = has_screenshots
        self.screenshots_count = screenshots_count
        self.main_screenshot_s3_bucket = main_screenshot_s3_bucket
        self.main_screenshot_s3_key = main_screenshot_s3_key
        self.response_count = response_count
        self.redirect_301_count = redirect_301_count
        self.redirect_302_count = redirect_302_count
        self.all_responses_redirects = all_responses_redirects
        self.all_responses_server_errors = all_responses_server_errors
        self.all_responses_client_errors = all_responses_client_errors
        self.response_statuses = response_statuses
        self.hostname_resolves = hostname_resolves
        self.resolved_ip_matches_hostname = resolved_ip_matches_hostname
        self.response_content_types = response_content_types
        self.www_authenticate_headers = www_authenticate_headers
        self.has_www_authenticate_headers = has_www_authenticate_headers
        self.has_basic_auth = has_basic_auth
        self.has_digest_auth = has_digest_auth
        self.has_ntlm_auth = has_ntlm_auth
        self.basic_auth_realms = basic_auth_realms
        self.has_server_headers = has_server_headers
        self.has_multiple_server_headers = has_multiple_server_headers
        self.all_responses_not_found = all_responses_not_found
        self.resolved_ip_address = resolved_ip_address
        self.ssl_certificate_cname = ssl_certificate_cname
        self.ssl_certificate_expired = ssl_certificate_expired
        self.ssl_certificate_is_valid = ssl_certificate_is_valid
        self.ssl_certificate_start_time = ssl_certificate_start_time
        self.ssl_certificate_invalid_time = ssl_certificate_invalid_time
        self.scan_completed_at = scan_completed_at
        self.hostname_is_ip_address = hostname_is_ip_address
        self.has_ssl_certificate_data = has_ssl_certificate_data
        self.ssl_certificate_md5_digest = ssl_certificate_md5_digest
        self.open_ports = open_ports
        self.landing_header_redirect_location = landing_header_redirect_location
        self.landing_meta_refresh_location = landing_meta_refresh_location
        self.landing_response_status = landing_response_status
        self.landing_title = landing_title
        self.local_login_form_count = local_login_form_count
        self.local_login_form_https_count = local_login_form_https_count
        self.remote_login_form_count = remote_login_form_count
        self.remote_login_form_https_count = remote_login_form_https_count
        self.user_agent_fingerprints = user_agent_fingerprints

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.uses_wordpress = RandomHelper.flip_coin()
        to_populate.uses_iss = RandomHelper.flip_coin()
        to_populate.uses_apache = RandomHelper.flip_coin()
        to_populate.uses_nginx = RandomHelper.flip_coin()
        to_populate.total_header_count = WsFaker.get_random_int(minimum=1, maximum=500)
        to_populate.unique_header_count = WsFaker.get_random_int(minimum=1, maximum=500)
        to_populate.server_headers = WsFaker.get_server_header_values()
        to_populate.transactions_count = WsFaker.get_random_int(minimum=1, maximum=500)
        to_populate.ok_count = WsFaker.get_random_int(minimum=1, maximum=500)
        to_populate.has_ok = to_populate.ok_count > 0
        to_populate.redirect_count = WsFaker.get_random_int(minimum=1, maximum=500)
        to_populate.has_redirect = to_populate.redirect_count > 0
        to_populate.client_error_count = WsFaker.get_random_int(minimum=1, maximum=500)
        to_populate.has_client_error = to_populate.client_error_count > 0
        to_populate.server_error_count = WsFaker.get_random_int(minimum=1, maximum=500)
        to_populate.has_server_error = to_populate.server_error_count > 0
        to_populate.total_resource_size = WsFaker.get_random_int(minimum=100000, maximum=500000)
        to_populate.uses_tomcat_management_portal = RandomHelper.flip_coin()
        to_populate.has_screenshots = RandomHelper.flip_coin()
        to_populate.screenshots_count = WsFaker.get_random_int(minimum=1, maximum=10)
        to_populate.main_screenshot_s3_bucket = WsFaker.get_s3_bucket()
        to_populate.main_screenshot_s3_key = WsFaker.get_s3_key()
        to_populate.response_count = WsFaker.get_random_int(minimum=1, maximum=10)
        to_populate.redirect_301_count = WsFaker.get_random_int(minimum=1, maximum=10)
        to_populate.redirect_302_count = WsFaker.get_random_int(minimum=1, maximum=10)
        to_populate.all_responses_redirects = RandomHelper.flip_coin()
        to_populate.all_responses_server_errors = RandomHelper.flip_coin()
        to_populate.all_responses_client_errors = RandomHelper.flip_coin()
        to_populate.response_statuses = WsFaker.get_http_response_statuses()
        to_populate.hostname_resolves = RandomHelper.flip_coin()
        to_populate.resolved_ip_matches_hostname = RandomHelper.flip_coin()
        to_populate.response_content_types = WsFaker.get_response_content_types()
        to_populate.www_authenticate_headers = WsFaker.get_words()
        to_populate.has_www_authenticate_headers = RandomHelper.flip_coin()
        to_populate.has_basic_auth = RandomHelper.flip_coin()
        to_populate.has_digest_auth = RandomHelper.flip_coin()
        to_populate.has_ntlm_auth = RandomHelper.flip_coin()
        to_populate.basic_auth_realms = WsFaker.get_words()
        to_populate.has_server_headers = RandomHelper.flip_coin()
        to_populate.has_multiple_server_headers = RandomHelper.flip_coin()
        to_populate.all_responses_not_found = RandomHelper.flip_coin()
        to_populate.resolved_ip_address = WsFaker.get_ipv4_address()
        to_populate.ssl_certificate_cname = WsFaker.get_domain_name()
        to_populate.ssl_certificate_expired = RandomHelper.flip_coin()
        to_populate.ssl_certificate_is_valid = RandomHelper.flip_coin()
        to_populate.ssl_certificate_start_time = WsFaker.get_time_in_past()
        to_populate.ssl_certificate_invalid_time = WsFaker.get_time_in_future()
        to_populate.scan_completed_at = DatetimeHelper.now()
        to_populate.hostname_is_ip_address = RandomHelper.flip_coin()
        to_populate.has_ssl_certificate_data = RandomHelper.flip_coin()
        to_populate.ssl_certificate_md5_digest = WsFaker.get_md5_string()
        to_populate.open_ports = WsFaker.get_web_app_open_ports()
        to_populate.landing_header_redirect_location = WsFaker.get_url()
        to_populate.landing_meta_refresh_location = WsFaker.get_url()
        to_populate.landing_response_status = WsFaker.get_http_response_status()
        to_populate.landing_title = " ".join(WsFaker.get_words())
        to_populate.local_login_form_count = WsFaker.get_random_int()
        to_populate.local_login_form_https_count = WsFaker.get_random_int()
        to_populate.remote_login_form_count = WsFaker.get_random_int()
        to_populate.remote_login_form_https_count = WsFaker.get_random_int()
        to_populate.user_agent_fingerprints = WsFaker.get_user_agent_fingerprints()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def update_fields(self):
        """
        Get a list of the fields owned by this model that should be used to update documents
        associated with the same web service scan.
        :return: a list of the fields owned by this model that should be used to update
        documents associated with the same web service scan.
        """
        return [
            "uses_wordpress",
            "uses_iis",
            "uses_apache",
            "uses_nginx",
            "total_header_count",
            "unique_header_count",
            "transactions_count",
            "ok_count",
            "has_ok",
            "redirect_count",
            "has_redirect",
            "client_error_count",
            "has_client_error",
            "server_error_count",
            "has_server_error",
            "total_resource_size",
            "uses_tomcat_management_portal",
        ]

    # Representation and Comparison


class WebServiceTechnologiesReportModel(BaseWebServiceScanModel):
    """
    This is an Elasticsearch model class for containing data about the technologies used by a web service
    as found during the course of a single web service scan.
    """

    # Class Members

    uses_wordpress = BooleanElasticsearchType()
    wordpress_version = KeywordElasticsearchType()
    uses_iis = BooleanElasticsearchType()
    iis_version = KeywordElasticsearchType()
    uses_apache = BooleanElasticsearchType()
    apache_version = KeywordElasticsearchType()
    uses_nginx = BooleanElasticsearchType()

    # Instantiation

    def __init__(
            self,
            uses_wordpress=None,
            wordpress_version=None,
            uses_iis=None,
            iis_version=None,
            uses_apache=None,
            apache_version=None,
            uses_nginx=None,
            **kwargs
    ):
        super(WebServiceTechnologiesReportModel, self).__init__(**kwargs)
        self.uses_wordpress = uses_wordpress
        self.wordpress_version = wordpress_version
        self.uses_iis = uses_iis
        self.iis_version = iis_version
        self.uses_apache = uses_apache
        self.apache_version = apache_version
        self.uses_nginx = uses_nginx

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.uses_wordpress = RandomHelper.flip_coin()
        to_populate.wordpress_version = WsFaker.get_version_string()
        to_populate.uses_iss = RandomHelper.flip_coin()
        to_populate.iis_version = WsFaker.get_version_string()
        to_populate.uses_apache = RandomHelper.flip_coin()
        to_populate.apache_version = WsFaker.get_version_string()
        to_populate.uses_nginx = RandomHelper.flip_coin()
        return to_populate

    # Public Methods

    def to_db_model_dict(self):
        """
        Get a dictionary containing the keys and values of this object that can be mapped to a WebServiceReport
        object to update in the database.
        :return: A dictionary containing the keys and values of this object that can be mapped to a WebServiceReport
        object to update in the database.
        """
        return {
            "uses_wordpress": self.uses_wordpress,
            "uses_apache": self.uses_apache,
            "uses_iis": self.uses_iis,
            "uses_nginx": self.uses_nginx,
        }

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class WebServiceHeadersReportModel(BaseWebServiceScanModel):
    """
    This is an Elasticsearch model class for containing data about the headers found in a web service during
    the course of a single web service scan.
    """

    # Class Members

    total_header_count = IntElasticsearchType()
    unique_header_count = IntElasticsearchType()
    server_headers = KeywordElasticsearchType()

    # Instantiation

    def __init__(
            self,
            total_header_count=None,
            unique_header_count=None,
            server_headers=[],
            **kwargs
    ):
        super(WebServiceHeadersReportModel, self).__init__(**kwargs)
        self.total_header_count = total_header_count
        self.unique_header_count = unique_header_count
        self.server_headers = server_headers

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.total_header_count = WsFaker.get_random_int(minimum=1, maximum=500)
        to_populate.unique_header_count = WsFaker.get_random_int(minimum=1, maximum=500)
        to_populate.server_headers = WsFaker.get_server_header_values()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
