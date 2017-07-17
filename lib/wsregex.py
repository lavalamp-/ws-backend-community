# -*- coding: utf-8 -*-
from __future__ import absolute_import

import re


class RegexLib(object):
    """
    A class containing all regular expressions used throughout the DataHound
    application.
    """

    # Class Members

    # Potentially better email regex
    # "([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,4})"
    # http://www.webmonkey.com/2008/08/four_regular_expressions_to_check_email_addresses/

    caps_alpha_regex = re.compile("^[A-Z]+$")
    cc_last_four_regex = re.compile("^[0-9]{4}$")
    docker_log_entry_regex = re.compile("^\[\d{4}-\d{2}-\d{2}")
    # domain_name_regex = re.compile("^[a-zA-Z0-9-*]+(\.[a-zA-Z0-9-]+)*$")
    domain_name_regex = re.compile("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$")
    email_regex = re.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,10}$")
    export_file_name_regex = re.compile("^[0-9A-Za-z_-]{1,32}$")
    file_log_entry_regex = re.compile("^\[\d{2}/\d{2}/\d{2} ")
    file_name_regex = re.compile("^[A-Za-z-_0-9]+$")
    first_name_regex = re.compile("^[A-Za-z\-']{1,32}$")
    hostname_regex = re.compile(
        "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z\-]*[A-Za-z])$",
        flags=re.IGNORECASE
    )
    html_form_regex = re.compile("<form.*?</form>", flags=re.IGNORECASE | re.DOTALL)
    integer_regex = re.compile("^[0-9]+$")
    ipv4_address_regex = re.compile(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",
        flags=re.IGNORECASE
    )
    ipv4_cidr_regex = re.compile(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$",
        flags=re.IGNORECASE
    )
    last_name_regex = re.compile("^[A-Za-z\-']{1,32}$")
    log_entry_stub_regex = re.compile("\[(.*?)\]")
    mime_string_regex = re.compile("^[a-z\-]+/[a-z\.\-_0-9]+(;(\s?[\w=\.\-]+)+)?$", flags=re.IGNORECASE)
    order_name_regex = re.compile("^[A-Za-z-_0-9]+$")
    protocol_regex = re.compile("^([A-Z]{1,10})://", flags=re.IGNORECASE)
    query_string_regex = re.compile(
        "^([\\\\\w\-!@\$%\^\*\(\)_`~+\[\]{}|;'\",<>]+=([\\\\\w\-!@\$%\^\*\(\)_`~+\[\]{}|;'\",<>]*)?(&[\\\\\w\-!@\$%\^\*\(\)_`~+\[\]{}|;'\",<>]+=([\\\\\w\-!@\$%\^\*\(\)_`~+\[\]{}|;'\",<>]*)?)*)$",
        flags=re.IGNORECASE,
    )
    url_port_regex = re.compile(".+:([1-9]([0-9]{1,10})?)$", flags=re.IGNORECASE)
    url_protocol_regex = re.compile("^([A-Z0-9-_]+?):", flags=re.IGNORECASE)
    url_scheme_regex = re.compile("^([A-Z0-9]{1,25})://", flags=re.IGNORECASE)
    user_name_regex = re.compile("^[A-Z0-9]{1,32}$", flags=re.IGNORECASE)
    uuid4_string_regex = re.compile(
        "^[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}$",
        flags=re.IGNORECASE,
    )
    zmap_bandwidth_regex = re.compile("^\d+[GMK]$")

    ssl_certificate_regex = re.compile("(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)", flags=re.DOTALL)
    authority_info_uri_regex = re.compile("URI:(.*)")
    basic_auth_realm_regex = re.compile("realm=\"(.*?)\"")
    card_last_four_regex = re.compile("^\d\d\d\d$")

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
