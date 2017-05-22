# -*- coding: utf-8 -*-
from __future__ import absolute_import

import socket

from lib.sqlalchemy import get_org_uuid_from_web_service_scan, get_hash_fingerprints_for_apache_tomcat, WebService, \
    get_web_service_uuid_from_web_service_scan, get_open_ports_for_web_service
from wselasticsearch import ElasticsearchQueryHelper
from wselasticsearch.models import SslSupportReportModel
from wselasticsearch.query import HttpScreenshotQuery, SslSupportReportQuery, WebResourceMultidocQuery, \
    HtmlWebResourceQuery, UserAgentFingerprintQuery
from wselasticsearch.query.aggregates import RangeAggregate, SumAggregate, TermsAggregate
from ..base import BaseInspector
from ...mixin import ElasticsearchableMixin
from lib import RegexLib, DatetimeHelper


class WebScanInspector(BaseInspector, ElasticsearchableMixin):
    """
    This is an inspector class that is responsible for analyzing the results of a single web service scan
    for the purpose of creating a single WebServiceReport.
    """

    # Class Members

    # Instantiation

    def __init__(self, web_scan_uuid=None, db_session=None):
        super(WebScanInspector, self).__init__()
        self._web_scan_uuid = web_scan_uuid
        self._wordpress_transactions = None
        self._es_query_helper = None
        self._org_uuid = None
        self._server_headers = None
        self._response_headers = None
        self._unique_header_count = None
        self._response_header_count = None
        self._transactions = None
        self._transactions_aggregates = None
        self._uses_tomcat_management_portal = None
        self._screenshots = None
        self._hostname_is_ip_address = None
        self._web_service = None
        self._web_service_uuid = None
        self._ip_address_resolved = False
        self._resolved_ip_address = None
        self._www_authenticate_headers = None
        self._basic_auth_headers = None
        self._digest_auth_headers = None
        self._ntlm_auth_headers = None
        self._basic_auth_realms = None
        self._response_404_count = None
        self._ssl_support_report = None
        self._ssl_support_retrieved = False
        self._open_ports_on_host = None
        self._landing_resource = None
        self._landing_resource_retrieved = False
        self._forms = None
        self._user_agent_fingerprints_response = None
        self._user_agent_fingerprints = None
        self.db_session = db_session

    # Static Methods

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import WebServiceReportModel
        return WebServiceReportModel

    # Public Methods

    # Protected Methods

    def _to_es_model(self):
        from wselasticsearch.models import WebServiceReportModel
        to_return = WebServiceReportModel(
            uses_wordpress=self.uses_wordpress,
            uses_iis=self.uses_iis,
            uses_apache=self.uses_apache,
            uses_nginx=self.uses_nginx,
            uses_tomcat_management_portal=self.uses_tomcat_management_portal,
            total_header_count=self.response_header_count,
            unique_header_count=self.unique_header_count,
            transactions_count=self.transactions_count,
            ok_count=self.ok_count,
            has_ok=self.ok_count > 0,
            redirect_count=self.redirect_count,
            has_redirect=self.redirect_count > 0,
            client_error_count=self.client_error_count,
            has_client_error=self.client_error_count > 0,
            server_error_count=self.server_error_count,
            has_server_error=self.server_error_count > 0,
            total_resource_size=self.total_resource_size,
            server_headers=self.server_headers,
            has_screenshots=self.has_screenshots,
            screenshots_count=self.screenshots_count,
            main_screenshot_s3_bucket=self.main_screenshot["s3_bucket"] if self.main_screenshot else None,
            main_screenshot_s3_key=self.main_screenshot["s3_key"] if self.main_screenshot else None,
            response_count=self.response_count,
            redirect_301_count=self.redirect_301_count,
            redirect_302_count=self.redirect_302_count,
            all_responses_redirects=self.all_responses_redirects,
            all_responses_server_errors=self.all_responses_server_errors,
            all_responses_client_errors=self.all_responses_client_errors,
            response_statuses=self.response_statuses,
            hostname_resolves=self.hostname_resolves,
            resolved_ip_matches_hostname=self.resolved_ip_matches_hostname,
            response_content_types=self.response_content_types,
            www_authenticate_headers=self.www_authenticate_headers,
            has_www_authenticate_headers=self.has_www_authenticate_headers,
            has_basic_auth=self.has_basic_auth,
            has_digest_auth=self.has_digest_auth,
            has_ntlm_auth=self.has_ntlm_auth,
            basic_auth_realms=self.basic_auth_realms,
            has_server_headers=self.has_server_headers,
            has_multiple_server_headers=self.has_multiple_server_headers,
            all_responses_not_found=self.all_responses_not_found,
            resolved_ip_address=self.resolved_ip_address,
            scan_completed_at=DatetimeHelper.now(),
            hostname_is_ip_address=self.hostname_is_ip_address,
            open_ports=self.open_ports,
            landing_header_redirect_location=self.landing_header_redirect_location,
            landing_meta_refresh_location=self.landing_meta_refresh_location,
            landing_response_status=self.landing_response_status,
            landing_title=self.landing_title,
            local_login_form_count=self.local_login_form_count,
            local_login_form_https_count=self.local_login_form_https_count,
            remote_login_form_count=self.remote_login_form_count,
            remote_login_form_https_count=self.remote_login_form_https_count,
            user_agent_fingerprints=self.user_agent_fingerprints,
        )
        to_return.populate_from_ssl_support(self.ssl_support_report)
        return to_return

    # Private Methods

    def __check_for_tomcat_management_portal(self):
        """
        Check to see whether the remote web service appears to be running the tomcat management portal.
        :return: True if the remote web service appears to be running the tomcat management portal, False
        otherwise.
        """
        tomcat_fingerprints = get_hash_fingerprints_for_apache_tomcat(self.db_session)
        query = WebResourceMultidocQuery(max_size=True)
        query.filter_by_web_service_scan(self.web_scan_uuid)
        for fingerprint in tomcat_fingerprints:
            query.or_by_wildcard(key="content_sha256_hash", value=fingerprint.hash)
        query.suppress_source = True
        result = query.search(self.org_uuid)
        return result.results_count > 0

    def __get_404_count(self):
        """
        Get the total number of 404 responses observed during the web service scan.
        :return: The total number of 404 responses observed during the web service scan.
        """
        query = WebResourceMultidocQuery(max_size=True, suppress_source=True)
        query.filter_by_web_service_scan(self.web_scan_uuid)
        query.filter_by_response_status(404)
        result = query.search(self.org_uuid)
        return result.results_count

    def __get_forms(self):
        """
        Get a list containing dictionaries representing all of the forms associated with the inspected
        web application.
        :return: A list containing dictionaries representing all of the forms associated with the inspected
        web application.
        """
        query = HtmlWebResourceQuery(max_size=True)
        query.filter_by_web_service_scan(self.web_scan_uuid)
        response = query.search(self.org_uuid)
        forms = []
        for result in response.results:
            result_forms = result["_source"].get("forms", [])
            forms.extend(result_forms)
        return forms

    def __get_landing_resource(self):
        """
        Get the resource that corresponds to the root-most URL path.
        :return: The resource that corresponds to the root-most URL path.
        """
        query = WebResourceMultidocQuery(size=1)
        query.filter_by_web_service_scan(self.web_scan_uuid)
        query.filter_by_url_path("/")
        result = query.search(self.org_uuid)
        if result.results_count > 0:
            return result.results[0]
        else:
            return None

    def __get_response_headers(self):
        """
        Get the Elasticsearch response from querying the web service scan for HTTP response headers.
        :return: A dictionary mapping response header keys (lowered) to lists of all the values observed
        for that response header key.
        """
        query = WebResourceMultidocQuery(size=10000)
        query.filter_by_web_service_scan(self.web_scan_uuid)
        query.queried_fields = ["response_headers"]
        query_result = query.search(self.org_uuid)
        to_return = {}
        for result in query_result.results:
            for response_header in result["_source"]["response_headers"]:
                if response_header["key"] not in to_return:
                    to_return[response_header["key"].lower()] = []
                to_return[response_header["key"].lower()].append(response_header["value"])
        return to_return

    def __get_response_header_count(self):
        """
        Get the total number of response headers that were observed while inspecting the given web service.
        :return: The total number of response headers that were observed while inspecting the given web service.
        """
        to_return = 0
        for k, v in self.response_headers.iteritems():
            to_return += len(v)
        return to_return

    def __get_screenshots(self):
        """
        Get an Elasticsearch response that contains all of the screenshots that were retrieved during the
        web service scan.
        :return: An Elasticsearch response that contains all of the screenshots that were retrieved during the
        web service scan.
        """
        query = HttpScreenshotQuery(max_size=True)
        query.filter_by_web_service_scan(self.web_scan_uuid)
        return query.search(self.org_uuid)

    def __get_ssl_support_report(self):
        """
        Get the SSL support report model associated with this web service's network service and hostname if such
        a report object exists.
        :return: The SSL support report model associated with this web service's network service and hostname if such
        a report object exists.
        """
        query = SslSupportReportQuery()
        query.filter_by_latest_scan()
        query.filter_by_network_service(self.web_service.network_service.uuid)
        result = query.search(self.org_uuid)
        if result.results_count > 0:
            return SslSupportReportModel.from_response_result(result.results[0])
        else:
            return None

    def __get_transactions(self):
        """
        Get an Elasticsearch response containing all of the transactions related to the web service scan.
        :return: an Elasticsearch response containing all of the transactions related to the web service scan.
        """
        query = WebResourceMultidocQuery(max_size=True)
        query.filter_by_web_service_scan(self.web_scan_uuid)
        query.filter_by_not_response_status(404)
        return query.search(self.org_uuid)

    def __get_transactions_aggregates(self):
        """
        Get an Elasticsearch response that contains aggregate data about the transactions associated
        with this web service scan.
        :return: an Elasticsearch response that contains aggregate data about the transactions
        associated with this web service scan.
        """
        query = WebResourceMultidocQuery(max_size=True, suppress_source=True)
        query.filter_by_web_service_scan(self.web_scan_uuid)
        response_status_aggregate = RangeAggregate(name="response_status", field="response_status")
        response_status_aggregate.add_range(range_from=200, range_to=299, key="ok_count")
        response_status_aggregate.add_range(range_from=300, range_to=399, key="redirect_count")
        response_status_aggregate.add_range(range_from=400, range_to=499, key="client_error_count")
        response_status_aggregate.add_range(range_from=500, range_to=599, key="server_error_count")
        query.add_aggregate(response_status_aggregate)
        query.aggregate_with_sum(key="content_length", name="content_length")
        query.aggregate_on_term(key="response_status", name="response_statuses")
        query.aggregate_on_term(key="content_type", name="content_types")
        query.filter_by_not_response_status(404)
        return query.search(self.org_uuid)

    def __get_user_agent_fingerprints(self):
        """
        Get an Elasticsearch response containing all of the user agent fingerprint results obtained during
        this web service scan.
        :return: An Elasticsearch response containing all of the user agent fingerprint results obtained during
        this web service scan.
        """
        query = UserAgentFingerprintQuery(max_size=True)
        query.filter_by_web_service_scan(self.web_scan_uuid)
        query.queried_fields = [
            "user_agent_type",
            "user_agent_name",
            "response_has_content",
            "response_mime_type",
            "response_primary_hash",
            "response_secondary_hash",
            "response_status_code",
        ]
        return query.search(self.org_uuid)

    def __get_unique_header_count(self):
        """
        Count the total number of unique HTTP response headers observed during the web service scan.
        :return: The total number of unique HTTP response headers observed during the web service scan.
        """
        headers = []
        for k, v in self.response_headers.iteritems():
            for value in v:
                headers.extend((k, value))
        return len(set(headers))

    def __get_wordpress_transactions(self):
        """
        Get an Elasticsearch response from a query that retrieves all HttpTransaction documents
        associated with self.web_scan_uuid that contain Wordpress-related resources.
        :return: An Elasticsearch response from a query that retrieves all HttpTransaction documents
        associated with self.web_scan_uuid that contain Wordpress-related resources.
        """
        query = WebResourceMultidocQuery(size=10000)
        query.filter_by_web_service_scan(self.web_scan_uuid)
        query.or_by_wildcard(key="url_path", value="wp-admin")
        query.or_by_wildcard(key="url_path", value="wp-content")
        return query.search(self.org_uuid)

    # Properties

    @property
    def all_responses_not_found(self):
        """
        Get whether or not all responses returned by the server during the scan were redirects.
        :return: whether or not all responses returned by the server during the scan were redirects.
        """
        return self.response_404_count > 0 and self.response_count == 0

    @property
    def all_responses_redirects(self):
        """
        Get whether or not all responses returned by the server during the scan were redirects.
        :return: whether or not all responses returned by the server during the scan were redirects.
        """
        return self.redirect_count == self.response_count and self.response_count > 0

    @property
    def all_responses_server_errors(self):
        """
        Get whether or not all responses returned by the server during the scan were server errors.
        :return: whether or not all responses returned by the server during the scan were server errors.
        """
        return self.server_error_count == self.response_count and self.response_count > 0

    @property
    def all_responses_client_errors(self):
        """
        Get whether or not all responses returned by the server during the scan were client errors.
        :return: whether or not all responses returned by the server during the scan were client errors.
        """
        return self.client_error_count == self.response_count and self.response_count > 0

    @property
    def basic_auth_headers(self):
        """
        Get a list of strings representing the WWW-Authenticate values for all basic auth headers.
        :return: a list of strings representing the WWW-Authenticate values for all basic auth headers.
        """
        if self._basic_auth_headers is None:
            self._basic_auth_headers = filter(lambda x: "basic" in x.lower(), self.www_authenticate_headers)
        return self._basic_auth_headers

    @property
    def basic_auth_realms(self):
        """
        Get the basic auth realms associated with the web service as found during the web service scan.
        :return: the basic auth realms associated with the web service as found during the web service scan.
        """
        if self._basic_auth_realms is None:
            realms = []
            for basic_auth_header in self.basic_auth_headers:
                realms.extend(RegexLib.basic_auth_realm_regex.findall(basic_auth_header))
            self._basic_auth_realms = realms
        return self._basic_auth_realms

    @property
    def client_error_count(self):
        """
        Get the number of HTTP client error responses returned when interacting with the remote service.
        :return: the number of HTTP client error responses returned when interacting with the remote service.
        """
        client_error_response = filter(
            lambda x: x["label"] == "client_error_count",
            self.response_status_distribution
        )[0]
        return client_error_response["count"]

    @property
    def digest_auth_headers(self):
        """
        Get a list of strings representing the WWW-Authenticate values for all digest auth headers.
        :return: a list of strings representing the WWW-Authenticate values for all digest auth headers.
        """
        if self._digest_auth_headers is None:
            self._digest_auth_headers = filter(lambda x: "digest" in x.lower(), self.www_authenticate_headers)
        return self._digest_auth_headers

    @property
    def es_query_helper(self):
        """
        Get an ElasticsearchQueryHelper to use to query Elasticsearch.
        :return: an ElasticsearchQueryHelper to use to query Elasticsearch.
        """
        if self._es_query_helper is None:
            self._es_query_helper = ElasticsearchQueryHelper.instance()
        return self._es_query_helper

    @property
    def forms(self):
        """
        Get a list containing dictionaries representing all of the forms contained in all of the HTML pages
        found within the inspected web application.
        :return: a list containing dictionaries representing all of the forms contained in all of the HTML
        pages found within the inspected web application.
        """
        if self._forms is None:
            self._forms = self.__get_forms()
        return self._forms

    @property
    def has_basic_auth(self):
        """
        Get whether or not the web service has any basic auth headers.
        :return: whether or not the web service has any basic auth headers.
        """
        return len(self.basic_auth_headers) > 0

    @property
    def has_digest_auth(self):
        """
        Get whether or not the web service has any digest auth headers.
        :return: whether or not the web service has any digest auth headers.
        """
        return len(self.digest_auth_headers) > 0

    @property
    def has_multiple_server_headers(self):
        """
        Get whether or not multiple server headers were observed in use by the web service.
        :return: whether or not multiple server headers were observed in use by the web service.
        """
        return len(self.server_headers) > 1

    @property
    def has_ntlm_auth(self):
        """
        Get whether or not the web service has any ntlm auth headers.
        :return: whether or not the web service has any ntlm auth headers.
        """
        return len(self.ntlm_auth_headers) > 0

    @property
    def has_server_headers(self):
        """
        Get whether or not server headers were observed during the web service scan.
        :return: whether or not server headers were observed during the web service scan.
        """
        return len(self.server_headers) > 0

    @property
    def has_screenshots(self):
        """
        Get whether or not this web service scan took any screenshots.
        :return: whether or not this web service scan took any screenshots.
        """
        return self.screenshots_count > 0

    @property
    def has_ssl_certificate_data(self):
        """
        Get whether or not this web service has any SSL certificate data associated with it.
        :return: whether or not this web service has any SSL certificate data associated with it.
        """
        return self.web_service.ssl_enabled and self.ssl_support_report is not None

    @property
    def has_www_authenticate_headers(self):
        """
        Get whether or not any WWW-Authenticate headers were observed during the web service scan.
        :return: Whether or not any WWW-Authenticate headers were observed during the web service scan.
        """
        return len(self.www_authenticate_headers) > 0

    @property
    def hostname_is_ip_address(self):
        """
        Get whether or not the hostname associated with the web service is an IP address.
        :return: whether or not the hostname associated with the web service is an IP address.
        """
        if self._hostname_is_ip_address is None:
            self._hostname_is_ip_address = self.web_service.host_name == self.web_service.ip_address
        return self._hostname_is_ip_address

    @property
    def hostname_resolves(self):
        """
        Get whether or not the hostname associated with the scanned web service resolves to an IP address.
        :return: whether or not the hostname associated with the scanned web service resolves to an IP address.
        """
        if self.hostname_is_ip_address:
            return True
        else:
            return self.resolved_ip_address is not None

    @property
    def landing_header_redirect_location(self):
        """
        Get the URL reference in the header redirect location found in the landing page for the analyzed web
        application if such a location exists.
        :return: the URL reference in the header redirect location found in the landing page for the
        analyzed web application if such a location exists.
        """
        return self.landing_resource["_source"].get("header_redirect_location", None) if self.landing_resource else None

    @property
    def landing_meta_refresh_location(self):
        """
        Get the URL reference in the meta refresh location found in the landing page for the analyzed web
        application if such a location exists.
        :return: the URL reference in the meta refresh location found in the landing page for the analyzed
        web application if such a location exists.
        """
        return self.landing_resource["_source"].get("meta_refresh_location", None) if self.landing_resource else None

    @property
    def landing_response_status(self):
        """
        Get the response status code found in the landing page for the web application.
        :return: the response status code found in the landing page for the web application.
        """
        return self.landing_resource["_source"]["response_status"]

    @property
    def landing_title(self):
        """
        Get the title of the landing page for the web application if the application has an HTML landing page.
        :return: the title of the landing page for the web application if the application has an HTML landing page.
        """
        return self.landing_resource["_source"].get("title", None) if self.landing_resource else None

    @property
    def landing_resource(self):
        """
        Get the resource that was retrieved from the root-most URL.
        :return: the resource that was retrieved from the root-most URL.
        """
        if self._landing_resource is None and not self._landing_resource_retrieved:
            self._landing_resource = self.__get_landing_resource()
            self._landing_resource_retrieved = True
        return self._landing_resource

    @property
    def local_login_form_count(self):
        """
        Get the number of login forms found on this web application that point to local resources.
        :return: the number of login forms found on this web application that point to local resources.
        """
        return len(filter(lambda x: x["has_password_input"] and x["internal_action"], self.forms))

    @property
    def local_login_form_https_count(self):
        """
        Get the number of login forms found on this web application that point to local resources and
        submit data over HTTPS.
        :return: the number of login forms found on this web application that point to local resources
        and submit data over HTTPS.
        """
        return len(filter(
            lambda x: x["has_password_input"]
                      and x["internal_action"]
                      and x["https_submission"],
            self.forms,
        ))

    @property
    def main_screenshot(self):
        """
        Get the main screenshot model to use for this report.
        :return: the main screenshot model to use for this report.
        """
        if self.has_screenshots:
            return self.screenshots.results[0]["_source"]
        else:
            return None

    @property
    def ntlm_auth_headers(self):
        """
        Get a list of strings representing the WWW-Authenticate values for all NTML auth headers.
        :return: a list of strings representing the WWW-Authenticate values for all NTLM auth headers.
        """
        if self._ntlm_auth_headers is None:
            self._ntlm_auth_headers = filter(lambda x: "ntml" in x.lower(), self.www_authenticate_headers)
        return self._ntlm_auth_headers

    @property
    def ok_count(self):
        """
        Get the number of HTTP OK responses returned when interacting with the remote service.
        :return: the number of HTTP OK responses returned when interacting with the remote service.
        """
        ok_response = filter(lambda x: x["label"] == "ok_count", self.response_status_distribution)[0]
        return ok_response["count"]

    @property
    def open_ports_on_host(self):
        """
        Get a list of tuples containing (1) the port number and (2) the protocol for all of the open ports found
        on the server where this web service resides.
        :return: A list of tuples containing (1) the port number and (2) the protocol for all of the open ports found
        on the server where this web service resides.
        """
        if self._open_ports_on_host is None:
            self._open_ports_on_host = get_open_ports_for_web_service(
                db_session=self.db_session,
                web_service_uuid=self.web_service_uuid,
            )
        return self._open_ports_on_host

    @property
    def org_uuid(self):
        """
        Get the UUID of the organization that the web service scan was run on behalf of.
        :return: the UUID of the organization that the web service scan was run on behalf of.
        """
        if self._org_uuid is None:
            self._org_uuid = get_org_uuid_from_web_service_scan(
                db_session=self.db_session,
                web_scan_uuid=self.web_scan_uuid,
            )
        return self._org_uuid

    @property
    def open_ports(self):
        """
        Get a list of dictionaries describing other open ports found on the host where this web service resides.
        :return: a list of dictionaries describing other open ports found on the host where this web service resides.
        """
        return [{"port": port, "protocol": protocol} for port, protocol in self.open_ports_on_host]

    @property
    def redirect_301_count(self):
        """
        Get the total number of 301 redirects found during the web service scan.
        :return: the total number of 301 redirects found during the web service scan.
        """
        count = filter(lambda x: x["label"] == 301, self.response_statuses)
        if len(count) > 0:
            return count[0]["count"]
        else:
            return 0

    @property
    def redirect_302_count(self):
        """
        Get the total number of 302 redirects found during the web service scan.
        :return: the total number of 302 redirects found during the web service scan.
        """
        count = filter(lambda x: x["label"] == 302, self.response_statuses)
        if len(count) > 0:
            return count[0]["count"]
        else:
            return 0

    @property
    def redirect_count(self):
        """
        Get the number of HTTP redirect responses returned when interacting with the remote service.
        :return: the number of HTTP redirect responses returned when interacting with the remote service.
        """
        redirect_response = filter(lambda x: x["label"] == "redirect_count", self.response_status_distribution)[0]
        return redirect_response["count"]

    @property
    def remote_login_form_count(self):
        """
        Get the number of login forms found on this web application that point to remote resources.
        :return: the number of login forms found on this web application that point to remote resources.
        """
        return len(filter(lambda x: x["has_password_input"] and not x["internal_action"], self.forms))

    @property
    def remote_login_form_https_count(self):
        """
        Get the number of login forms found on this web application that point to remote resources and
        submit data over HTTPS.
        :return: the number of login forms found on this web application that point to remote resources
        and submit data over HTTPS.
        """
        return len(filter(
            lambda x: x["has_password_input"]
                      and not x["internal_action"]
                      and x["https_submission"],
            self.forms,
        ))

    @property
    def resolved_ip_address(self):
        """
        Get the IP address that the hostname of the web service resolves to.
        :return: the IP address that the hostname of the web service resolves to.
        """
        if not self._ip_address_resolved:
            if not self.hostname_is_ip_address:
                try:
                    self._resolved_ip_address = socket.gethostbyname(self.web_service.host_name)
                except socket.gaierror:
                    self._resolved_ip_address = None
            else:
                self._resolved_ip_address = self.web_service.ip_address
            self._ip_address_resolved = True
        return self._resolved_ip_address

    @property
    def resolved_ip_matches_hostname(self):
        """
        Get whether or not the IP address the hostname resolves to matches the web service's IP address.
        :return: whether or not the IP address the hostname resolves to matches the web service's IP address.
        """
        return self.resolved_ip_address == self.web_service.ip_address

    @property
    def response_404_count(self):
        """
        Get the total number of 404 responses observed during the web service scan.
        :return: the total number of 404 responses observed during the web service scan.
        """
        if self._response_404_count is None:
            self._response_404_count = self.__get_404_count()
        return self._response_404_count

    @property
    def response_content_types(self):
        """
        Get a dictionary mapping content types to the number of resources found of that content type during
        the web service scan.
        :return: a dictionary mapping content types to the number of resources found of that content type
        during the web service scan.
        """
        return TermsAggregate.unpack_response(self.transactions_aggregates.aggregations["content_types"])

    @property
    def response_count(self):
        """
        Get the total number of non-404 responses seen during the web service scan.
        :return: The total number of non-404 responses seen during the web service scan.
        """
        return self.transactions.results_count

    @property
    def response_headers(self):
        """
        Get the Elasticsearch response from querying the web service scan for HTTP response headers.
        :return: the Elasticsearch response from querying the web service scan for HTTP response headers.
        """
        if self._response_headers is None:
            self._response_headers = self.__get_response_headers()
        return self._response_headers

    @property
    def response_header_count(self):
        """
        Get the total number of response headers retrieved during the web service scan.
        :return: the total number of response headers retrieved during the web service scan.
        """
        if self._response_header_count is None:
            self._response_header_count = self.__get_response_header_count()
        return self._response_header_count

    @property
    def response_status_distribution(self):
        """
        Get a list of dictionaries representing the counts of various response status types incurred
        while inspecting the remote web service.
        :return: a list of dictionaries representing the counts of various response status types
        incurred while inspecting the remote web service.
        """
        return RangeAggregate.unpack_response(self.transactions_aggregates.aggregations["response_status"])

    @property
    def response_statuses(self):
        """
        Get a dictionary mapping HTTP response status codes to their counts found during the web service scan.
        :return: a dictionary mapping HTTP response status codes to their counts found during the web service scan.
        """
        to_return = TermsAggregate.unpack_response(self.transactions_aggregates.aggregations["response_statuses"])
        if self.response_404_count > 0:
            to_return.append({
                "label": 404,
                "count": self.response_404_count,
            })
        to_return = sorted(to_return, key=lambda x: x["label"])
        return to_return

    @property
    def screenshots(self):
        """
        Get an Elasticsearch response that contains all of the screenshots taken during the inspection.
        :return: an Elasticsearch response that contains all of the screenshots taken during the inspection.
        """
        if self._screenshots is None:
            self._screenshots = self.__get_screenshots()
        return self._screenshots

    @property
    def screenshots_count(self):
        """
        Get the total number of screenshots retrieved during this web service scan.
        :return: the total number of screenshots retrieved during this web service scan.
        """
        return self.screenshots.results_count

    @property
    def server_headers(self):
        """
        Get a list of the Server HTTP response header values found across all of the transactions
        associated with this web service scan.
        :return: a list of the Server HTTP response header values found across all of the
        transactions associated with this web service scan.
        """
        if self._server_headers is None:
            self._server_headers = list(set(self.response_headers.get("server", [])))
        return self._server_headers

    @property
    def server_error_count(self):
        """
        Get the number of HTTP server error responses returned when interacting with the remote service.
        :return: the number of HTTP server error responses returned when interacting with the remote service.
        """
        server_error_response = filter(
            lambda x: x["label"] == "server_error_count",
            self.response_status_distribution
        )[0]
        return server_error_response["count"]

    @property
    def ssl_certificate_cname(self):
        """
        Get the CName value of the SSL certificate associated with this web service.
        :return: the CName value of the SSL certificate associated with this web service.
        """
        return self.ssl_support_report.cert_subject_common_name if self.ssl_support_report else None

    @property
    def ssl_certificate_expired(self):
        """
        Get whether or not the SSL certificate associated with this web service is expired.
        :return: whether or not the SSL certificate associated with this web service is expired.
        """
        return self.ssl_support_report.cert_expired if self.ssl_support_report else None

    @property
    def ssl_certificate_is_valid(self):
        """
        Get whether or not the SSL certificate associated with this web service is valid.
        :return: whether or not the SSL certificate associated with this web service is valid.
        """
        return self.ssl_support_report.cert_is_valid if self.ssl_support_report else None

    @property
    def ssl_certificate_start_time(self):
        """
        Get the time at which the SSL certificate associated with this web service starts being valid.
        :return: the time at which the SSL certificate associated with this web service starts being valid.
        """
        return self.ssl_support_report.cert_start_time if self.ssl_support_report else None

    @property
    def ssl_certificate_invalid_time(self):
        """
        Get the time at which the SSL certificate associated with this web service stops being valid.
        :return: the time at which the SSL certificate associated with this web service stops being valid.
        """
        return self.ssl_support_report.cert_invalid_time if self.ssl_support_report else None

    @property
    def ssl_support_report(self):
        """
        Get the SSL support report document associated with this web service's network service if the web
        service uses SSL.
        :return: the SSL support report document associated with this web service's network service if the
        web service uses SSL.
        """
        if not self._ssl_support_retrieved is None and self.web_service.ssl_enabled:
            self._ssl_support_report = self.__get_ssl_support_report()
            self._ssl_support_retrieved = True
        return self._ssl_support_report

    @property
    def total_resource_size(self):
        """
        Get the cumulative size of all the resources served by the web server during the web service scan.
        :return: the cumulative size of all the resources served by the web server during the web service scan.
        """
        return SumAggregate.unpack_response(self.transactions_aggregates.aggregations["content_length"])

    @property
    def transactions_count(self):
        """
        Get the total number of transactions incurred while inspecting the related web service.
        :return: the total number of transactions incurred while inspecting the related web service.
        """
        return self.transactions.results_count

    @property
    def transactions(self):
        """
        Get an Elasticsearch response containing all of the transactions related to the web service scan.
        :return: an Elasticsearch response containing all of the transactions related to the web service scan.
        """
        if self._transactions is None:
            self._transactions = self.__get_transactions()
        return self._transactions

    @property
    def transactions_aggregates(self):
        """
        Get an Elasticsearch response that contains aggregate data about the transactions associated
        with this web service scan.
        :return: an Elasticsearch response that contains aggregate data about the transactions
        associated with this web service scan.
        """
        if self._transactions_aggregates is None:
            self._transactions_aggregates = self.__get_transactions_aggregates()
        return self._transactions_aggregates

    @property
    def unique_header_count(self):
        """
        Count the total number of unique HTTP response headers observed during the web service scan.
        :return: The total number of unique HTTP response headers observed during the web service scan.
        """
        if self._unique_header_count is None:
            self._unique_header_count = self.__get_unique_header_count()
        return self._unique_header_count

    @property
    def user_agent_fingerprints(self):
        """
        Get a list of dictionaries representing the user agent fingerprinting results gathered during
        this web service scan.
        :return: a list of dictionaries representing the user agent fingerprinting results gathered during
        this web service scan.
        """
        if self._user_agent_fingerprints is None:
            fingerprints = []
            for result in self.user_agent_fingerprints_response.results:
                result_source = result["_source"]
                fingerprints.append({
                    "user_agent_type": result_source["user_agent_type"],
                    "user_agent_name": result_source["user_agent_name"],
                    "response_has_content": result_source["response_has_content"],
                    "response_mime_type": result_source["response_mime_type"],
                    "response_primary_hash": result_source["response_primary_hash"],
                    "response_secondary_hash": result_source["response_secondary_hash"],
                    "response_status_code": result_source["response_status_code"],
                })
            self._user_agent_fingerprints = fingerprints
        return self._user_agent_fingerprints

    @property
    def user_agent_fingerprints_response(self):
        """
        Get an Elasticsearch response containing all of the user agent fingerprints retrieved during the
        given web service scan.
        :return: an Elasticsearch response containing all of the user agent fingerprints retrieved during
        the given web service scan.
        """
        if self._user_agent_fingerprints_response is None:
            self._user_agent_fingerprints_response = self.__get_user_agent_fingerprints()
        return self._user_agent_fingerprints_response

    @property
    def uses_apache(self):
        """
        Get whether or not the results of the web service scan indicate that the web service is using Apache.
        :return: whether or not the results of the web service scan indicate that the web service is using Apache.
        """
        return any(["apache" in x.lower() for x in self.server_headers])

    @property
    def uses_iis(self):
        """
        Get whether or not the results of the web service scan indicate that the web service is using IIS.
        :return: whether or not the results of the web service scan indicate that the web service is using IIS.
        """
        return any(["iis" in x.lower() for x in self.server_headers])

    @property
    def uses_nginx(self):
        """
        Get whether or not the results of the web service scan indicate that the web service is using Nginx.
        :return: whether or not the results of the web service scan indicate that the web service is using Nginx.
        """
        return any(["nginx" in x.lower() for x in self.server_headers])

    @property
    def uses_tomcat_management_portal(self):
        """
        Get whether or not the results of the web service scan indicate that the web service is running
        Apache Tomcat management portal.
        :return: whether or not the results of the web service scan indicate that the web service is running
        Apache Tomcat management portal.
        """
        if self._uses_tomcat_management_portal is None:
            self._uses_tomcat_management_portal = self.__check_for_tomcat_management_portal()
        return self._uses_tomcat_management_portal

    @property
    def uses_wordpress(self):
        """
        Get whether or not the results of the web service scan indicate that the web service
        is running Wordpress.
        :return: whether or not the results of the web service scan indicate that the web
        service is running Wordpress.
        """
        return self.wordpress_transactions.results_count > 0

    @property
    def web_scan_uuid(self):
        """
        Get the UUID of the web service scan that this inspector is responsible for analyzing.
        :return: the UUID of the web service scan that this inspector is responsible for analyzing.
        """
        return self._web_scan_uuid

    @property
    def web_service(self):
        """
        Get the web service model that this scan scanned.
        :return: the web service model that this scan scanned.
        """
        if self._web_service is None:
            self._web_service = WebService.by_uuid(uuid=self.web_service_uuid, db_session=self.db_session)
        return self._web_service

    @property
    def web_service_uuid(self):
        """
        Get the UUID of the web service that was scanned during this web service scan.
        :return: the UUID of the web service that was scanned during this web service scan.
        """
        if self._web_service_uuid is None:
            self._web_service_uuid = get_web_service_uuid_from_web_service_scan(
                scan_uuid=self.web_scan_uuid,
                db_session=self.db_session,
            )
        return self._web_service_uuid

    @property
    def wordpress_transactions(self):
        """
        Get an Elasticsearch response from a query that retrieves all HttpTransaction documents
        associated with self.web_scan_uuid that contain Wordpress-related resources.
        :return: an Elasticsearch response from a query that retrieves all HttpTransaction
        documents associated with self.web_scan_uuid that contain Wordpress-related resources.
        """
        if self._wordpress_transactions is None:
            self._wordpress_transactions = self.__get_wordpress_transactions()
        return self._wordpress_transactions

    @property
    def www_authenticate_headers(self):
        """
        Get a list containing all of the header values for WWW-Authenticate headers found during the
        web service scan.
        :return: a list containing all of the header values for WWW-Authenticate headers found during
        the web service scan.
        """
        if self._www_authenticate_headers is None:
            self._www_authenticate_headers = self.response_headers.get("www-authenticate", [])
        return self._www_authenticate_headers

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.web_scan_uuid)

