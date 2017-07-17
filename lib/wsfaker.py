# -*- coding: utf-8 -*-
from __future__ import absolute_import

import calendar

from faker import Faker
from uuid import uuid4
import random
from base64 import b64encode
from OpenSSL import crypto
from datetime import timedelta
import Geohash

from .conversion import ConversionHelper
from .wsdatetime import DatetimeHelper
from .host import HostHelper
from .crypto import RandomHelper, HashHelper
from .config import ConfigManager
from .aws import S3Helper
from .filesystem import FilesystemHelper

faker = Faker()
config = ConfigManager.instance()


class WsFaker(object):
    """
    A class for creating dummy data specific to the Web Sight application.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def create_class_c_networks(length=20):
        """
        Create and return a list of strings containing class C networks.
        :param length: The number of class C networks to create.
        :return: A list of strings containing class C networks.
        """
        ips = WsFaker.create_ip_addresses(length=length)
        return [ConversionHelper.ipv4_to_class_c(x) for x in ips]

    @staticmethod
    def create_ip_addresses(length=20):
        """
        Create and return a list of strings containing IPv4 addresses.
        :param length: The number of IPv4 addresses to include in the list.
        :return: A list of strings containing IPv4 addresses.
        """
        return [faker.ipv4() for i in range(length)]

    @staticmethod
    def create_uuid():
        """
        Create and return a UUID string.
        :return: A UUID string.
        """
        return unicode(uuid4())

    @staticmethod
    def create_uuids(count=5):
        """
        Create and return a list of UUIDs of the specified length (as strings).
        :param count: The number of UUIDs to return.
        :return: A list of UUIDs in string format.
        """
        return [WsFaker.create_uuid() for i in range(count)]

    @staticmethod
    def get_all_mime_strings():
        """
        Get a list of all the MIME strings that WsFaker chooses between.
        :return: A list of all the MIME strings that WsFaker chooses between.
        """
        return [
            "application/atom+xml",
            "application/java-archive",
            "application/javascript",
            "application/json",
            "application/vnd.anser-web-certificate-issue-initiation",
            "text/html",
            "text/csv",
            "text/css",
        ]

    @staticmethod
    def get_card_last_four():
        """
        Get a string that represents that last four digits of a credit card number.
        :return: A string that represents the last four digits of a credit card number.
        """
        number = random.sample(range(9999), 1)[0]
        return str(number).rjust(4, "0")

    @staticmethod
    def get_card_type():
        """
        Get a string representing a credit card type.
        :return: A string representing a credit card type.
        """
        return random.sample([
            "American Express",
            "Visa",
            "Mastercard",
            "Discover",
        ], 1)[0]

    @staticmethod
    def get_certificate_extensions(count=5):
        """
        Get a list of dictionaries representing SSL certificate extensions.
        :param count: The number of extensions to add.
        :return: A list of dictionaries representing SSL certificate extensions.
        """
        to_return = []
        for i in range(count):
            to_return.append({
                "extension_name": WsFaker.get_word(),
                "extension_content": ", ".join(WsFaker.get_words(count=10)),
            })
        return to_return

    @staticmethod
    def get_city():
        """
        Get a string depicting a city.
        :return: A string depicting a city.
        """
        return faker.city()

    @staticmethod
    def get_command_line():
        """
        Get a string representing a tool invoked from command line.
        :return: A string representing a tool invoked from command line.
        """
        return "foo bar baz -w output -i input --bandwidth=50M"

    @staticmethod
    def get_country_code():
        """
        Get a string depicting a country code.
        :return: A string depicting a country code.
        """
        return faker.country_code()

    @staticmethod
    def get_directory_path():
        """
        Get a random path that ends in a directory.
        :return: A random path that ends in a directory.
        """
        path_length = WsFaker.get_random_int(minimum=1, maximum=5)
        path_segments = WsFaker.get_words(count=path_length)
        return "/%s/" % ("/".join(path_segments),)

    @staticmethod
    def get_dns_record_content():
        """
        Get a string representing the contents of a DNS record.
        :return: A string representing the contents of a DNS record.
        """
        return faker.paragraph(1)

    @staticmethod
    def get_dns_record_type():
        """
        Get a DNS record type supported by Web Sight.
        :return: A DNS record type supported by Web Sight.
        """
        return random.sample(WsFaker.get_dns_record_types(), 1)[0]

    @staticmethod
    def get_dns_record_types():
        """
        Get a list containing all of the DNS record types supported by Web Sight.
        :return: A list containing all of the DNS record types supported by Web Sight.
        """
        contents = FilesystemHelper.get_file_contents(path=config.files_dns_record_types_path)
        contents = [x.strip() for x in contents.strip().split("\n")]
        to_return = []
        for line in contents:
            line_split = [x.strip() for x in line.split(",")]
            if line_split[1] == "True":
                to_return.append(line_split[0])
        return to_return

    @staticmethod
    def get_domain_discovery_method():
        """
        Get a string representing a method through which a domain name is discovered during
        a domain name scan.
        :return: A string representing a method through which a domain name is discovered during
        a domain name scan.
        """
        return random.sample(["database", "brute-forcing"], 1)[0]

    @staticmethod
    def get_domain_history_collection_method():
        """
        Get a string depicting one of the methods that Web Sight uses to collect domain history for an
        IP address.
        :return: a string depicting one of the methods that Web Sight uses to collect domain history for
        an IP address.
        """
        return random.sample(["dnsdb"], 1)[0]

    @staticmethod
    def get_domain_name():
        """
        Get a random domain name.
        :return: A random domain name.
        """
        return faker.domain_name()

    @staticmethod
    def get_domain_names(count=5):
        """
        Get a list of domain names.
        :param count: The number of domain names to return.
        :return: A list of domain names.
        """
        return [WsFaker.get_domain_name() for i in range(count)]

    @staticmethod
    def get_domain_related_ips(count=5):
        """
        Get a list of dictionaries representing IP addresses related to a domain name.
        :param count: The number of dictionaries to return.
        :return: A list of dictionaries representing IP addresses related to a domain name.
        """
        to_return = []
        for i in range(count):
            to_return.append({
                "ip_address": WsFaker.get_ipv4_address(),
                "ip_address_uuid": WsFaker.create_uuid(),
            })
        return to_return

    @staticmethod
    def get_domain_resolutions(count=5):
        """
        Get a list of dictionaries representing domain name resolutions.
        :param count: The number of resolutions to return.
        :return: a list of dictionaries representing domain name resolutions.
        """
        to_return = []
        for i in range(count):
            to_return.append({
                "record_type": WsFaker.get_dns_record_type(),
                "record_contents": [WsFaker.get_ipv4_address()]
            })
        return to_return

    @staticmethod
    def get_expiration_year():
        """
        Get an integer that represents a credit card expiration year.
        :return: An integer that represents a credit card expiration year.
        """
        time_in_future = random.sample(range(20), 1)[0]
        return DatetimeHelper.now().year + time_in_future

    @staticmethod
    def get_file_extension():
        """
        Get a random file extension.
        :return: A random file extension.
        """
        return faker.file_extension()

    @staticmethod
    def get_file_name():
        """
        Get a random file name.
        :return: A random file name.
        """
        return faker.file_name()

    @staticmethod
    def get_file_path():
        """
        Get a random path that ends in a file.
        :return: A random path that ends in a file.
        """
        dir_path = WsFaker.get_directory_path()
        return "%s%s" % (dir_path, WsFaker.get_file_name())

    @staticmethod
    def get_fingerprint_service_name():
        """
        Get the name of a service that fingerprinting is currently available for.
        :return: The name of a service that fingerprinting is currently available for.
        """
        from lib.fingerprinting import get_all_supported_fingerprint_services
        service_names = get_all_supported_fingerprint_services()
        return random.sample(service_names, 1)[0]

    @staticmethod
    def get_function_name():
        """
        Create and return a string that represents a function name.
        :return: A string representing a function name.
        """
        return faker.name()

    @staticmethod
    def get_geohash():
        """
        Get a Geohash value.
        :return: A Geohash value.
        """
        return Geohash.encode(faker.latitude(), faker.longitude())

    @staticmethod
    def get_geo_source():
        """
        Get a string depicting a source where geolocation data is retrieved from.
        :return: A string depicting a source where geolocation data is retrieved from.
        """
        return random.sample(["ipapi"], 1)[0]

    @staticmethod
    def get_html_form():
        """
        Get a dictionary representing an HTML form to be submitted to Elasticsearch.
        :return: A dictionary representing an HTML form to be submitted to Elasticsearch.
        """
        has_action = RandomHelper.flip_coin()
        action = WsFaker.get_url() if has_action else None
        resolved_action = action
        has_method = RandomHelper.flip_coin()
        method = WsFaker.get_http_request_method() if has_method else None
        return {
            "has_action": has_action,
            "action": action,
            "resolved_action": resolved_action,
            "has_method": has_method,
            "method": method,
            "inputs": WsFaker.get_html_inputs(),
        }

    @staticmethod
    def get_html_forms(count=2):
        """
        Get a list of dictionaries representing HTML forms.
        :param count: The number of dictionaries to return.
        :return: A list of dictionaries representing HTML forms.
        """
        return [WsFaker.get_html_form() for i in range(count)]

    @staticmethod
    def get_html_input():
        """
        Get a dictionary representing an HTML input tag to be submitted to Elasticsearch.
        :return: A dictionary representing an HTML input tag to be submitted to Elasticsearch.
        """
        has_type = RandomHelper.flip_coin()
        input_type = WsFaker.get_html_input_type() if has_type else None
        has_name = RandomHelper.flip_coin()
        name = WsFaker.get_word() if has_name else None
        has_value = RandomHelper.flip_coin()
        value = WsFaker.get_word() if has_value else None
        return {
            "has_type": has_type,
            "type": input_type,
            "has_name": has_name,
            "name": name,
            "has_value": has_value,
            "value": value,
        }

    @staticmethod
    def get_html_inputs(count=5):
        """
        Get a list of HTML input dictionaries.
        :param count: The number of HTML input dictionaries to retrieve.
        :return: A list of HTML input dictionaries.
        """
        return [WsFaker.get_html_input() for i in range(count)]

    @staticmethod
    def get_html_input_type():
        """
        Get a string representing an HTML input tag type.
        :return: A string representing an HTML input tag type.
        """
        return random.sample(["radio", "text", "password", "email", "date"], 1)[0]

    @staticmethod
    def get_html_tag_counts(count=5):
        """
        Get a list of dictionaries representing HTML tag counts.
        :param count: The number of dictionaries to return.
        :return: A list of dictionaries representing HTML tag counts.
        """
        to_return = []
        for i in range(count):
            tag_name = WsFaker.get_html_tag_name()
            to_return.append({
                "tag": tag_name,
                "count": WsFaker.get_random_int()
            })
        return to_return

    @staticmethod
    def get_html_tag_name():
        """
        Get a string representing an HTML tag name.
        :return: A string representing an HTML tag name.
        """
        return random.sample(["a", "div", "p", "ul", "li"], 1)[0]

    @staticmethod
    def get_http_argument_key():
        """
        Get a string representing an HTTP argument key.
        :return: A string representing an HTTP argument key.
        """
        return WsFaker.get_http_header_key()

    @staticmethod
    def get_http_argument_tuple():
        """
        Get a tuple containing (1) an HTTP argument key and (2) an HTTP argument value.
        :return: A tuple containing (1) an HTTP argument key and (2) an HTTP argument value.
        """
        return WsFaker.get_http_argument_key(), WsFaker.get_http_argument_value()

    @staticmethod
    def get_http_arguments(minimum=1, maximum=5):
        """
        Get a random number of HTTP argument tuples.
        :param minimum: The minimum number of tuples to return.
        :param maximum: The maximum number of tuples to return.
        :return: A random number of HTTP argument tuples.
        """
        arg_count = WsFaker.get_random_int(minimum=minimum, maximum=maximum)
        to_return = []
        for i in range(arg_count):
            to_return.append({
                "key": WsFaker.get_http_argument_key(),
                "value": WsFaker.get_http_argument_value(),
            })
        return to_return

    @staticmethod
    def get_http_argument_value():
        """
        Get a string representing an HTTP argument value.
        :return: A string representing an HTTP argument value.
        """
        return WsFaker.get_http_header_value()

    @staticmethod
    def get_http_header_key():
        """
        Get a string representing an HTTP header key.
        :return: A string representing an HTTP header key.
        """
        word_count = WsFaker.get_random_int(minimum=1, maximum=4)
        words = WsFaker.get_words(count=word_count)
        return "-".join([x.title() for x in words])

    @staticmethod
    def get_http_header_tuple():
        """
        Get a tuple containing (1) an HTTP header key and (2) an HTTP header value.
        :return: A tuple containing (1) an HTTP header key and (2) an HTTP header value.
        """
        return WsFaker.get_http_header_key(), WsFaker.get_http_header_value()

    @staticmethod
    def get_http_headers(minimum=1, maximum=5):
        """
        Get a random number of HTTP header tuples.
        :param minimum: The minimum number of tuples to return.
        :param maximum: The maximum number of tuples to return.
        :return: A random number of HTTP header tuples.
        """
        header_count = WsFaker.get_random_int(minimum=minimum, maximum=maximum)
        to_return = []
        for i in range(header_count):
            to_return.append({
                "key": WsFaker.get_http_header_key(),
                "value": WsFaker.get_http_header_value(),
            })
        return to_return

    @staticmethod
    def get_http_header_value():
        """
        Get a string representing an HTTP header value.
        :return: A string representing an HTTP header value.
        """
        joiner = random.sample([".", ",", "-", "_"], 1)[0]
        return joiner.join(WsFaker.get_words(count=5))

    @staticmethod
    def get_http_request_method():
        """
        Get a string representing an HTTP verb.
        :return: A string representing an HTTP verb.
        """
        http_verbs = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "CONNECT", "PATCH"]
        return random.sample(http_verbs, 1)[0]

    @staticmethod
    def get_http_response_status():
        """
        Get an integer representing an HTTP response status.
        :return: An integer representing an HTTP response status.
        """
        http_statuses = [200, 201, 202, 204, 400, 401, 403, 404, 500, 502]
        return random.sample(http_statuses, 1)[0]

    @staticmethod
    def get_http_response_statuses(count=5, minimum=1, maximum=999999):
        """
        Get a list of dictionaries mapping HTTP status codes to the number of responses associated
        with that response code.
        :param count: The number of response status codes to add.
        :param minimum: The minimum number of occurences.
        :param maximum: The maximum number of occurences.
        :return: A list of dictionaries mapping HTTP status codes to the number of responses associated
        with that response code.
        """
        codes = [WsFaker.get_http_response_status() for x in range(count)]
        codes = list(set(codes))
        to_return = []
        for code in codes:
            to_return.append({
                "count": WsFaker.get_random_int(minimum=minimum, maximum=maximum),
                "label": code,
            })
        return to_return

    @staticmethod
    def get_ipv4_address():
        """
        Create and return a random IPv4 address.
        :return: A random IPv4 address.
        """
        return faker.ipv4()

    @staticmethod
    def get_ip_address_type():
        """
        Get a string representing an IP address type.
        :return: A string representing an IP address type.
        """
        return random.sample(["ipv4", "ipv6"], 1)[0]

    @staticmethod
    def get_latitude():
        """
        Get a decimal value representing a latitude.
        :return: A decimal value representing a latitude.
        """
        return faker.latitude()

    @staticmethod
    def get_longitude():
        """
        Get a decimal value representing a longitude.
        :return: A decimal value representing a longitude.
        """
        return faker.longitude()

    @staticmethod
    def get_md5_string():
        """
        Get an MD5 hash as a string.
        :return: an MD5 hash as a string.
        """
        paragraph = ", ".join(WsFaker.get_words(count=10))
        return HashHelper.md5_digest(paragraph)

    @staticmethod
    def get_mime_string():
        """
        Get a string containing a valid MIME type.
        :return: A string containing a valid MIME type.
        """
        all_mime_strings = WsFaker.get_all_mime_strings()
        return random.sample(all_mime_strings, 1)[0]

    @staticmethod
    def get_month_int():
        """
        Get an integer that represents a month.
        :return: An integer that represents a month.
        """
        return random.sample(range(12), 1)[0] + 1

    @staticmethod
    def get_network_cidr_range():
        """
        Get a dictionary representing a CIDR range that follows the Elasticsearch CIDR range type.
        :return: A dictionary representing a CIDR range that follows the Elasticsearch CIDR range type.
        """
        return {
            "network_address": WsFaker.get_ipv4_address(),
            "mask_length": WsFaker.get_random_int(minimum=1, maximum=32)
        }

    @staticmethod
    def get_networks(count=5):
        """
        Get a list containing strings representing CIDR network ranges.
        :param count: The number of CIDR network range strings to return.
        :return: A list containing strings representing CIDR network ranges.
        """
        ip_addresses = WsFaker.create_ip_addresses(length=count)
        return [ConversionHelper.ipv4_to_class_c(x) for x in ip_addresses]

    @staticmethod
    def get_network_name():
        """
        Get a string representing a network name.
        :return: A string representing a network name.
        """
        return faker.word()

    @staticmethod
    def get_network_protocol():
        """
        Create and return a string representing a network protocol.
        :return: A string representing a network protocol.
        """
        return random.sample(["tcp", "udp", "sctp"], 1)[0]

    @staticmethod
    def get_network_service_discovery_method():
        """
        Get a string describing a method through which a network service can be discovered.
        :return: A string describing a method through which a network service can be discovered.
        """
        return random.sample(["network scan", "domain scan"], 1)[0]

    @staticmethod
    def get_organization_kwargs():
        """
        Get keyword arguments to pass to Organization.objects.create.
        :return: Keyword arguments to pass to Organization.objects.create.
        """
        return {
            "name": WsFaker.get_word(),
            "description": ", ".join(WsFaker.get_words())
        }

    @staticmethod
    def get_past_time(minutes=None):
        """
        Create and return a datetime that is a random amount of time ago.
        :param minutes: The maximum number of minutes ago that the time should be.
        :return: A datetime that is a random amount of time ago.
        """
        if minutes is not None:
            minutes_past = random.randint(0, minutes)
            return DatetimeHelper.minutes_ago(minutes_past)
        else:
            raise ValueError("No arguments passed to past_time were not None.")

    @staticmethod
    def get_path():
        """
        Get a random path (can be a directory or a file).
        :return: A random path (can be a directory or a file).
        """
        use_dir = RandomHelper.flip_coin()
        if use_dir:
            return WsFaker.get_directory_path()
        else:
            return WsFaker.get_file_path()

    @staticmethod
    def get_port(minimum=1, maximum=65535):
        """
        Get a valid port integer between the specified minimum and maximum.
        :param minimum: The minimum port number.
        :param maximum: The maximum port number.
        :return: A valid port integer between the specified minimum and maximum.
        """
        return random.randrange(minimum, maximum+1)

    @staticmethod
    def get_ports(minimum=1, maximum=65535, count=5):
        """
        Get the specified number of valid port integers.
        :param minimum: The minumum port number.
        :param maximum: The maximum port number.
        :param count: The number of ports to return.
        :return: A list containing the specified number of port integers.
        """
        return [WsFaker.get_port(minimum=minimum, maximum=maximum) for i in range(count)]

    @staticmethod
    def get_port_scan_method():
        """
        Get a string depicting one of the methods used by Web Sight to conduct port scans.
        :return: A string depicting one of the methods used by Web Sight to conduct port scans.
        """
        return random.sample(["nmap"], 1)[0]

    @staticmethod
    def get_port_state():
        """
        Get a string depicting the state of a network port.
        :return: A string depicting the state of a network port.
        """
        return random.sample(["open", "closed"], 1)[0]

    @staticmethod
    def get_port_statuses(count=5):
        """
        Get a list of dictionaries matching the PortStatusElasticsearchType.
        :param count: The number of dictionaries to return.
        :return: A list of dictionaries matching the PortStatusElasticsearchType.
        """
        to_return = []
        for i in range(count):
            to_return.append({
                "port_number": WsFaker.get_port(),
                "port_status": WsFaker.get_port_state(),
                "port_protocol": WsFaker.get_network_protocol(),
            })

    @staticmethod
    def get_random_int(minimum=1, maximum=999999):
        """
        Get a random integer in the given range.
        :param minimum: The minimum possible value.
        :param maximum: The maximum possible value.
        :return: A random integer in the given range.
        """
        return random.randint(minimum, maximum)

    @staticmethod
    def get_random_ints(count=5, minimum=1, maximum=999999):
        """
        Get a list of random integers.
        :param count: The number of integers to return.
        :param minimum: The minimum value for integers.
        :param maximum: The maximum value for integers.
        :return: A list of random integers.
        """
        return [WsFaker.get_random_int(minimum=minimum, maximum=maximum) for i in range(count)]

    @staticmethod
    def get_region():
        """
        Get a string depicting a region.
        :return: A string depicting a region.
        """
        return faker.state_abbr()

    @staticmethod
    def get_response_content_types(count=5, minimum=1, maximum=9999999):
        """
        Get a list of dictionaries mapping content types to the occurence counts.
        :param count: The number of content types.
        :param minimum: The minimum number of occurences.
        :param maximum: The maximum number of occurences.
        :return: A list of dictionaries mapping content types to the occurence counts.
        """
        mime_types = [WsFaker.get_mime_string() for i in range(count)]
        mime_types = list(set(mime_types))
        to_return = []
        for mime_type in mime_types:
            to_return.append({
                "count": WsFaker.get_random_int(minimum=minimum, maximum=maximum),
                "label": mime_type,
            })
        return to_return

    @staticmethod
    def get_server_header_value():
        """
        Get a string representing a server header value.
        :return: A string representing a server header value.
        """
        return "apache"

    @staticmethod
    def get_server_header_values(count=5):
        """
        Get a list of strings containing server header values.
        :param count: The number of strings to return.
        :return: A list of strings containing server header values.
        """
        return [WsFaker.get_server_header_value() for x in range(count)]

    @staticmethod
    def get_sha256_string():
        """
        Get a string containing a SHA256 hash.
        :return: A string containing a SHA256 hash.
        """
        return HashHelper.sha256_digest(WsFaker.get_web_resource())

    @staticmethod
    def get_ssl_certificate(key=None, as_string=True, dump_type=crypto.FILETYPE_PEM):
        """
        Create and return an SSL certificate.
        :param key: The OpenSSL key to use to generate the certificate.
        :param as_string: Whether or not to return the SSL certificate as a string instead of
        an OpenSSL certificate.
        :param dump_type: The certificate output type to return the string in.
        :return: An SSL certificate.
        """
        cert = crypto.X509()
        if key is None:
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 1024)
        cert.get_subject().C = faker.country_code()
        cert.get_subject().ST = faker.state()
        cert.get_subject().L = faker.city()
        cert.get_subject().O = "Web Sight.IO, LLC"
        cert.get_subject().OU = "Supah Coders"
        cert.get_subject().CN = WsFaker.get_ssl_subject_name()
        cert.set_serial_number(WsFaker.get_random_int())
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(WsFaker.get_time_in_future(as_datetime=False))
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, "sha1")
        if as_string:
            return crypto.dump_certificate(dump_type, cert)
        else:
            return cert

    @staticmethod
    def get_ssl_subject_name():
        """
        Create and return an SSL subject name.
        :return: An SSL subject name.
        """
        return "%s.dummy.websight.io" % (faker.domain_word(),)

    @staticmethod
    def get_ssl_version_name():
        """
        Get a random SSL version name.
        :return: A random SSL version name.
        """
        ssl_version_names = HostHelper.get_available_ssl_version_names()
        return random.sample(ssl_version_names, 1)[0]

    @staticmethod
    def get_ssl_vuln_test_results(count=2):
        """
        Get a list containing dictionaries that represent SSL vulnerability test results.
        :return: A list containing dictionaries that represent SSL vulnerability test results.
        """
        to_return = []
        for i in range(count):
            to_return.append({
                "key": WsFaker.get_word(),
                "value": RandomHelper.flip_coin(),
            })
        return to_return

    @staticmethod
    def get_state_code():
        """
        Get a string depicting a state code.
        :return: A string depicting a state code.
        """
        return faker.state_abbr()

    @staticmethod
    def get_street_address():
        """
        Get a string depicting a street address.
        :return: A string depicting a street address.
        """
        return faker.street_address()

    @staticmethod
    def get_stripe_token():
        """
        Get a stripe token value.
        :return: A stripe token value.
        """
        return "tok_19xg6sE6xi5DHYsI80fJIOYY"

    @staticmethod
    def get_subdomains(count=5):
        """
        Get a list of dictionaries representing subdomains for Elasticsearch.
        :param count: The number of dictionaries to return.
        :return: A list of dictionaries representing subdomains for Elasticsearch.
        """
        to_return = []
        for i in range(count):
            to_return.append({
                "subdomain": WsFaker.get_domain_name(),
                "domain_uuid": WsFaker.create_uuid(),
            })
        return to_return

    @staticmethod
    def get_s3_link():
        """
        Create and return an AWS S3 link.
        :return: An AWS S3 link.
        """
        return "s3://foo/bar/baz"

    @staticmethod
    def get_s3_bucket():
        """
        Get a string representing an AWS S3 bucket.
        :return: A string representing an AWS S3 bucket.
        """
        return config.aws_s3_bucket

    @staticmethod
    def get_s3_file_type():
        """
        Get a string representing an S3 file type.
        :return: A string representing an S3 file type.
        """
        return random.sample(["ssl certificate", "http screenshot"], 1)[0]

    @staticmethod
    def get_s3_key():
        """
        Get a string representing an S3 file key.
        :return: A string representing an S3 file key.
        """
        s3_helper = S3Helper.instance()
        path_component = WsFaker.get_s3_path_component()
        return s3_helper.get_key(
            org_uuid=WsFaker.create_uuid(),
            path_component=path_component,
        )

    @staticmethod
    def get_s3_mixin_dictionary():
        """
        Get a dictionary that can be unpacked as arguments to the S3Mixin.set_s3_attributes method.
        :return: A dictionary that can be unpacked as arguments to the S3Mixin.set_s3_attributes method.
        """
        return {
            "bucket": WsFaker.get_s3_bucket(),
            "key": WsFaker.get_s3_key(),
            "file_type": WsFaker.get_s3_file_type(),
        }

    @staticmethod
    def get_s3_path_component():
        """
        Get a string representing an S3 key path component.
        :return: A string representing an S3 key path component.
        """
        return random.sample(["ssl-certificate", "http-screenshot"], 1)[0]

    @staticmethod
    def get_task_function_name():
        """
        Create and return a string that represents the name of a task used by Web Sight.
        :return: A string that represents the name of a task used by Web Sight.
        """
        return faker.name()

    @staticmethod
    def get_time_in_future(minimum=1, maximum=99999, as_datetime=True):
        """
        Get a datetime that represents a time in the future.
        :param minimum: The minimum number of minutes from now.
        :param maximum: The maximum number of minutes from now.
        :param as_datetime: Whether to return the result as a datetime or UTC seconds.
        :return: A datetime that represents a time in the future.
        """
        minutes_from_now = WsFaker.get_random_int(minimum=minimum, maximum=maximum)
        future_date = DatetimeHelper.minutes_from_now(minutes_from_now)
        if as_datetime:
            return future_date
        else:
            return calendar.timegm(future_date.utctimetuple())

    @staticmethod
    def get_timedelta(minimum=1, maximum=99999):
        """
        Get a timedelta from a random amount of minutes in the past.
        :param minimum: The minimum number of minutes in the past.
        :param maximum: The maximum number of minutes in the past.
        :return: A timedelta representing a random amount of minutes in the past.
        """
        return timedelta(minutes=WsFaker.get_random_int(minimum=minimum, maximum=maximum))

    @staticmethod
    def get_time_in_past(minimum=1, maximum=99999, as_datetime=True):
        """
        Get a datetime that represents a time in the past.
        :param minimum: The minimum number of minutes in the past.
        :param maximum: The maximum number of minutes in the past.
        :param as_datetime: Whether to return the result as a datetime or UTC seconds.
        :return: A datetime that represents a time in the past.
        """
        minutes_in_past = WsFaker.get_random_int(minimum=minimum, maximum=maximum)
        past_date = DatetimeHelper.minutes_ago(minutes_in_past)
        if as_datetime:
            return past_date
        else:
            return calendar.timegm(past_date.utctimetuple())

    @staticmethod
    def get_traceback(base64_encoded=False):
        """
        Get a string representing an error traceback.
        :param base64_encoded: Whether or not to base64 encode the result.
        :return: A string representing an error traceback, base64 encoded if base64_encoded is
        True.
        """
        faker = Faker()
        to_return = faker.paragraph()
        if base64_encoded:
            to_return = b64encode(to_return)
        return to_return

    @staticmethod
    def get_url():
        """
        Get a random URL string.
        :return: A random URL string.
        """
        uses_https = RandomHelper.flip_coin()
        domain_name = WsFaker.get_domain_name()
        port = WsFaker.get_port()
        path = WsFaker.get_path()
        return "%s://%s:%s%s" % (
            "https" if uses_https else "http",
            domain_name,
            port,
            path,
        )

    @staticmethod
    def get_user_agent():
        """
        Create and return a fake user agent.
        :return: A fake user agent.
        """
        return 'Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US);'

    @staticmethod
    def get_user_agent_fingerprints(count=5):
        """
        Get a list of dictionaries representing user agent fingerprints.
        :param count: The number of dictionaries to return.
        :return: A list of dictionaries representing user agent fingerprints.
        """
        to_return = []
        for i in range(count):
            to_return.append({
                "user_agent_type": WsFaker.get_word(),
                "user_agent_name": WsFaker.get_word(),
                "response_has_content": WsFaker.get_user_agent(),
                "response_mime_type": WsFaker.get_mime_string(),
                "response_primary_hash": WsFaker.get_sha256_string(),
                "response_secondary_hash": WsFaker.get_sha256_string(),
                "response_status_code": WsFaker.get_http_response_status(),
            })
        return to_return

    @staticmethod
    def get_version_string(minor_count=3):
        """
        Get a string that represents a version.
        :param minor_count: The number of sub versions to include in the string.
        :return: A string that represents a version.
        """
        versions = [WsFaker.get_random_int(minimum=1, maximum=9) for x in range(minor_count)]
        return ".".join([str(x) for x in versions])

    @staticmethod
    def get_vhost_discovery_method():
        """
        Get a string representing a virtual host discovery method used by Web Sight.
        :return: A string representing a virtual host discovery method used by Web Sight.
        """
        return random.sample(["status-code", "has-content", "mime-type", "content-hash", "baseline"], 1)[0]

    @staticmethod
    def get_web_app_open_ports(count=5):
        """
        Get a list of dictionaries to use as contents of other open ports for web application report
        models.
        :param count: The number of dictionaries to include in the response.
        :return: A list of dictionaries to use as contents of other open ports for web application report
        models.
        """
        to_return = []
        for i in range(count):
            to_return.append({
                "protocol": WsFaker.get_network_protocol(),
                "port": WsFaker.get_port(),
            })
        return to_return

    @staticmethod
    def get_web_resource():
        """
        Get a string representing a resource retrieved from the web.
        :return: A string representing a resource retrieved from the web.
        """
        return faker.paragraph()

    @staticmethod
    def get_whois_networks(count=5):
        """
        Get a list of dictionaries representing WhoisNetworkElasticsearchType data.
        :param count: The number of dictionaries to return.
        :return: A list of dictionaries representing WhoisNetworkElasticsearchType data.
        """
        to_return = []
        for i in range(count):
            to_return.append({
                "whois_org_name": WsFaker.get_word(),
                "whois_org_handle": WsFaker.get_word(),
                "whois_org_country_code": WsFaker.get_country_code(),
                "whois_network_handle": WsFaker.get_word(),
                "whois_network_name": WsFaker.get_word(),
                "whois_network_range": WsFaker.get_network_cidr_range(),
            })
        return to_return

    @staticmethod
    def get_word():
        """
        Get a single word.
        :return: A string containing a single word.
        """
        return faker.word()

    @staticmethod
    def get_words(count=5):
        """
        Get a list containing the specified number of words.
        :param count: The number of words to return.
        :return: A list containing the specified number of words.
        """
        return faker.words(count)

    @staticmethod
    def get_zip_code():
        """
        Get a string depicting a zip code.
        :return: A string depicting a zip code.
        """
        return faker.zipcode()

    @staticmethod
    def get_zmap_scan_bandwidth():
        """
        Get a string representing a Zmap scan bandwidth.
        :return: A string representing a Zmap scan bandwidth.
        """
        speed = WsFaker.get_random_int(minimum=1, maximum=1000)
        speed_type = random.sample(["K", "G", "M"], 1)[0]
        return "%s%s" % (speed, speed_type)

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
