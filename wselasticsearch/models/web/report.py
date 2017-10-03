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

    uses_wordpress = BooleanElasticsearchType(
        help_text="Whether or not the web service uses Wordpress.",
    )
    uses_iis = BooleanElasticsearchType(
        help_text="Whether or not the web service uses IIS.",
    )
    uses_apache = BooleanElasticsearchType(
        help_text="Whether or not the web service uses Apache HTTP server.",
    )
    uses_nginx = BooleanElasticsearchType(
        help_text="Whether or not the web service uses Nginx.",
    )
    total_header_count = IntElasticsearchType(
        help_text="The total number of headers that were returned by the web service.",
    )
    unique_header_count = IntElasticsearchType(
        help_text="The total number of unique headers that were returned by the web "
                  "service.",
    )
    server_headers = KeywordElasticsearchType(
        help_text="The Server HTTP response headers returned by the web service.",
    )
    transactions_count = IntElasticsearchType(
        help_text="The total number of HTTP transactions performed against the web service.",
    )
    ok_count = IntElasticsearchType(
        help_text="The total number of HTTP 200 OK responses that were observed during testing "
                  "of the web service.",
    )
    has_ok = BooleanElasticsearchType(
        help_text="Whether or not a single HTTP 200 OK response was returned by the web service.",
    )
    redirect_count = IntElasticsearchType(
        help_text="The total number of HTTP redirects that were returned by the web service during testing.",
    )
    has_redirect = BooleanElasticsearchType(
        help_text="Whether or not a single HTTP redirect response was returned by the web service.",
    )
    client_error_count = IntElasticsearchType(
        help_text="The total number of HTTP client error responses that were returned by the web service "
                  "during testing.",
    )
    has_client_error = BooleanElasticsearchType(
        help_text="Whether or not a single HTTP client error response was returned by the web service.",
    )
    server_error_count = IntElasticsearchType(
        help_text="The total number of HTTP server error responses that were returned by the web service "
                  "during testing.",
    )
    has_server_error = BooleanElasticsearchType(
        help_text="Whether or not a single HTTP server error response was returned by the web service.",
    )
    total_resource_size = IntElasticsearchType(
        help_text="The cumulative size (in bytes) of all resources returned by the web service.",
    )
    uses_tomcat_management_portal = BooleanElasticsearchType(
        help_text="Whether or not the web service uses Tomcat Management Portal.",
    )
    has_screenshots = BooleanElasticsearchType(
        help_text="Whether or not screenshots were taken for the web service.",
    )
    screenshots_count = IntElasticsearchType(
        help_text="The total number of screenshots taken for the web service.",
    )
    main_screenshot_s3_bucket = KeywordElasticsearchType(
        help_text="The storage bucket where the main screenshot for the web service is stored.",
    )
    main_screenshot_s3_key = KeywordElasticsearchType(
        help_text="The storage key where the main screenshot for the web service is stored.",
    )
    response_count = IntElasticsearchType(
        help_text="The total number of responses that were returned by the web service during "
                  "testing.",
    )
    redirect_301_count = IntElasticsearchType(
        help_text="The total number of HTTP 301 redirects that were returned by the server.",
    )
    redirect_302_count = IntElasticsearchType(
        help_text="The total number of HTTP 302 redirects that were returned by the server.",
    )
    all_responses_redirects = BooleanElasticsearchType(
        help_text="Whether or not all responses returned by the server were redirects.",
    )
    all_responses_server_errors = BooleanElasticsearchType(
        help_text="Whether or not all responses returned by the server were server errors.",
    )
    all_responses_client_errors = BooleanElasticsearchType(
        help_text="Whether or not all responses returned by the server were client errors.",
    )
    response_statuses = CountDataPointElasticsearchType(
        help_text="All of the unique HTTP status codes that were returned by the web service.",
    )
    hostname_resolves = BooleanElasticsearchType(
        help_text="Whether or not the hostname associated with the web service resolves.",
    )
    resolved_ip_matches_hostname = BooleanElasticsearchType(
        help_text="Whether or not he IP address that the web service's hostname resolves to is the "
                  "IP address associated with this web service.",
    )
    response_content_types = CountDataPointElasticsearchType(
        help_text="The unique MIME types that were returned by all the requests to the web service.",
    )
    www_authenticate_headers = KeywordElasticsearchType(
        help_text="All of the HTTP authentication headers that were returned by the web service.",
    )
    has_www_authenticate_headers = BooleanElasticsearchType(
        help_text="Whether or not the web service returned at least one HTTP authentication header.",
    )
    has_basic_auth = BooleanElasticsearchType(
        help_text="Whether or not the web service uses HTTP basic authentication.",
    )
    has_digest_auth = BooleanElasticsearchType(
        help_text="Whether or not the web service uses HTTP diget authentication.",
    )
    has_ntlm_auth = BooleanElasticsearchType(
        help_text="Whether or not the web service uses HTTP NTLM authentication.",
    )
    basic_auth_realms = KeywordElasticsearchType(
        help_text="The realms that the HTTP basic auth used by the web service authenticate against.",
    )
    has_server_headers = BooleanElasticsearchType(
        help_text="Whether or not the web service returned at least one server header.",
    )
    has_multiple_server_headers = BooleanElasticsearchType(
        help_text="Whether or not multiple differing server headers were returned by the web service.",
    )
    all_responses_not_found = BooleanElasticsearchType(
        help_text="Whether or not all responses from the web service were 404 not founds.",
    )
    resolved_ip_address = KeywordElasticsearchType(
        help_text="The IP address that the web service's hostname resolves to.",
    )
    scan_completed_at = DateElasticsearchType(
        help_text="The time at which the web service scan completed.",
    )
    hostname_is_ip_address = BooleanElasticsearchType(
        help_text="Whether or not the hostname associated with this web service contains an IP "
                  "address.",
    )
    open_ports = KeywordIntKeyValueElasticsearchType(
        key_name="protocol",
        value_name="port",
        help_text="The ports that were open on the host where this web service resides.",
    )
    landing_header_redirect_location = KeywordElasticsearchType(
        help_text="The HTTP response location header location for the landing page of the web service if "
                  "such a header is returned by the landing page.",
    )
    landing_meta_refresh_location = KeywordElasticsearchType(
        help_text="The <meta> redirect tag location for the landing page of the web service if the "
                  "landing page contains such a tag."
    )
    landing_response_status = IntElasticsearchType(
        help_text="The HTTP status code for the landing page of the web service.",
    )
    landing_title = KeywordElasticsearchType(
        help_text="The contents of the <title> tag on the landing page for this web service.",
    )
    local_login_form_count = IntElasticsearchType(
        help_text="The total number of login forms that post to this web service.",
    )
    local_login_form_https_count = IntElasticsearchType(
        help_text="The total number of login forms that post to this web service over SSL/TLS.",
    )
    remote_login_form_count = IntElasticsearchType(
        help_text="The total number of login forms that post to other web services from this web service.",
    )
    remote_login_form_https_count = IntElasticsearchType(
        help_text="The total number of login forms that post to other web services from this web service "
                  "over SSL/TLS.",
    )
    user_agent_fingerprints = UserAgentFingerprintElasticsearchType(
        help_text="The fingerprinting results from testing for different responses from differing user "
                  "agents against this web service.",
    )

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
