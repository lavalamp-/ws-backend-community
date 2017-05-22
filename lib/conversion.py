# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
from OpenSSL import crypto
from datetime import datetime

from .config import ConfigManager
from .validation import ValidationHelper
from .crypto import HashHelper
from .exception import ConversionError

config = ConfigManager.instance()


class ConversionHelper(object):
    """
    A helper class for converting data representations to various other types.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def ipv4_to_class_c(ipv4_address):
        """
        Get a string representing the class C network that contains the specified
        IPv4 address.
        :param ipv4_address: The IPv4 address to process.
        :return: A string representing the class C network that contains the specified
        IPv4 address.
        """
        return "%s/24" % (ConversionHelper.ipv4_to_class_c_prefix(ipv4_address),)

    @staticmethod
    def ipv4_to_class_c_cidr_tuple(ipv4_address):
        """
        Get a tuple containing (1) the CIDR prefix as a string and (2) the CIDR mask length as
        an integer for the class C network that contains the specified IPv4 address.
        :param ipv4_address: The IPv4 address to process.
        :return: A tuple containing (1) the CIDR prefix as a string and (2) the CIDR mask length as
        an integer for the class C network that contains the specified IPv4 address.
        """
        return ConversionHelper.ipv4_to_class_c_prefix(ipv4_address), 24

    @staticmethod
    def ipv4_to_class_c_prefix(ipv4_address):
        """
        Get a string representing the CIDR prefix for the class C network that contains ipv4_address.
        :param ipv4_address: The IPv4 address to process.
        :return: A string representing the CIDR prefix for the class C network that contains ipv4_address.
        """
        return "%s.0" % (ipv4_address[:ipv4_address.rfind(".")],)

    @staticmethod
    def mime_wrapper_to_mime_type(mime_wrapper):
        """
        Process the MimeWrapper instance in mime_wrapper and return a MIME type constant
        representing the type of data the wrapper represents.
        :param mime_wrapper: The MimeWrapper to process.
        :return: A constant reflecting the MIME type mime_wrapper references.
        """
        if mime_wrapper.type_string == "text" and mime_wrapper.subtype == "html":
            return "html"
        elif mime_wrapper.type_string in ["application", "text"] and "xml" in mime_wrapper.subtype:
            return "xml"
        elif mime_wrapper.type_string in ["application", "text"] and mime_wrapper.subtype in ["javascript", "x-javascript", "ecmascript"]:
            return "javascript"
        elif mime_wrapper.type_string == "application" and mime_wrapper.subtype == "pdf":
            return "pdf"
        elif mime_wrapper.type_string == "text" and mime_wrapper.subtype == "css":
            return "css"
        elif mime_wrapper.type_string == "image":
            return "image"
        elif mime_wrapper.type_string in ["audio", "image", "video"]:
            return "media"
        elif mime_wrapper.type_string == "application" and mime_wrapper.subtype == "json":
            return "json"
        elif mime_wrapper.type_string == "text":
            return "text"
        else:
            return "unknown"

    @staticmethod
    def network_ranges_to_zmap_list(network_ranges):
        """
        Convert a list of network range tuples to a Zmap list file.
        :param network_ranges: A list of network range tuples (address and CIDR mask length).
        :return: A string representing a Zmap list file.
        """
        cidr_ranges = []
        for network_range in network_ranges:
            cidr_ranges.append("/".join([str(x) for x in network_range]))
        return "\n".join(cidr_ranges)

    @staticmethod
    def pyopenssl_protocol_name_from_ssl_version(ssl_version):
        """
        Parse the contents of ssl_version and return a string depicting the PyOpenSSL version
        that Python should use to invoke the protocol.
        :param ssl_version: A string representing the SSL version to check.
        :return: A string representing the PyOpenSSL protocol mapped to the given SSL version.
        """
        if ssl_version == "sslv2":
            return "PROTOCOL_SSLv23"
        elif ssl_version == "sslv3":
            return "PROTOCOL_SSLv3"
        elif ssl_version == "tlsv1":
            return "PROTOCOL_TLSv1"
        elif ssl_version == "tlsv1.1":
            return "PROTOCOL_TLSv1_1"
        elif ssl_version == "tlsv1.2":
            return "PROTOCOL_TLSv1_2"
        else:
            raise ValueError(
                "Unsure what PyOpenSSL protocol to use for SSL version %s."
                % (ssl_version,)
            )

    @staticmethod
    def string_to_log_level(input_string):
        """
        Get the logging level corresponding to the given string.
        :param input_string: The string to process.
        :return: None
        """
        ValidationHelper.validate_log_level_string(input_string)
        if input_string == "DEBUG":
            return logging.DEBUG
        elif input_string == "INFO":
            return logging.INFO
        elif input_string == "WARNING":
            return logging.WARNING
        elif input_string == "ERROR":
            return logging.ERROR
        elif input_string == "CRITICAL":
            return logging.CRITICAL
        else:
            raise ValueError(
                "Unsure how to handle log level of %s."
                % (input_string,)
            )

    @staticmethod
    def string_to_unicode(input_string, encoding=config.gen_default_encoding):
        """
        Convert the string passed to this method to unicode, if it isn't in unicode format
        already. The encoding specified by encoding is used to decode the string to unicode.
        :param input_string: The string to convert to unicode.
        :param encoding: The encoding to use to decode the string.
        :return: The input string in unicode format.
        """
        if input_string is None:
            return input_string
        return input_string if isinstance(input_string, unicode) else input_string.decode(encoding)

    @staticmethod
    def ssl_certificate_to_hash(certificate=None, output_type=crypto.FILETYPE_PEM):
        """
        Convert the given SSL certificate to a hash representing its contents.
        :param certificate: The certificate to parse.
        :param output_type: The SSL certificate output type.
        :return: A SHA256 hash representing the contents of the given certificate.
        """
        cert_string = ConversionHelper.ssl_certificate_to_string(
            certificate=certificate,
            output_type=output_type,
        )
        return HashHelper.sha256_digest(cert_string)

    @staticmethod
    def ssl_certificate_to_string(certificate=None, output_type=crypto.FILETYPE_PEM):
        """
        Convert the given SSL certificate to a string of the given type.
        :param certificate: The certificate to parse.
        :param output_type: The SSL certificate output type.
        :return: The given certificate in string format.
        """
        return crypto.dump_certificate(cert=certificate, type=output_type)

    @staticmethod
    def ssl_timestamp_to_datetime(ssl_timestamp):
        """
        Convert the given SSL timestamp into a Python datetime.
        :param ssl_timestamp: The SSL timestamp to convert.
        :return: A Python datetime representing the time passed in ssl_timestamp.
        """
        return datetime.strptime(ssl_timestamp, "%Y%m%d%H%M%SZ")

    @staticmethod
    def string_to_boolean(to_convert):
        """
        Convert the contents of to_convert into a boolean.
        :param to_convert: A string to convert to a boolean.
        :return: A boolean representing the contents of to_convert.
        """
        to_convert = to_convert.strip().lower()
        if to_convert == "true":
            return True
        elif to_convert == "false":
            return False
        else:
            raise ConversionError(
                "Could not convert string %s to boolean."
                % (to_convert,)
            )

    @staticmethod
    def string_to_html_link_tag_type(rel_string):
        """
        Map the contents of rel_string to an HTML link element tag type.
        :param rel_string: The string to evaluate.
        :return: A constant representing the link tag type matching rel_string.
        """
        rel_string = rel_string.lower().strip()
        if rel_string == "search":
            return "search"
        elif rel_string == "canonical":
            return "canonical"
        elif rel_string == "alternate":
            return "alternate"
        elif rel_string == "dns-prefetch":
            return "dns-prefetch"
        elif rel_string == "preconnect":
            return "preconnect"
        elif rel_string == "icon":
            return "icon"
        elif rel_string == "shortcut icon":
            return "icon"
        elif rel_string == "apple-touch-icon-precomposed":
            return "apple icons"
        elif rel_string == "stylesheet":
            return "stylesheet"
        else:
            raise ValueError(
                "No link tag type found for string %s."
                % (rel_string,)
            )

    @staticmethod
    def string_to_html_meta_tag_type(meta_string):
        """
        Map the contents of meta_string to an HTML meta tag element type.
        :param meta_string: The string to evaluate.
        :return: A constant representing the meta tag type matching meta_string.
        """
        meta_string = meta_string.lower().strip()
        if meta_string == "keywords":
            return "keywords"
        elif meta_string == "description":
            return "description"
        elif meta_string == "referrer":
            return "referrer"
        elif meta_string == "viewport":
            return "viewport"
        else:
            raise ValueError(
                "No meta tag type found for string %s."
                % (meta_string,)
            )

    @staticmethod
    def string_to_html_script_tag_type(type_string):
        """
        Map the contents of type_string to an HTML script element type.
        :param type_string: The string to evaluate.
        :return: A constant representing the script content type matching type_string.
        """
        type_string = type_string.lower().strip()
        if type_string == "text/javascript":
            return "javascript"
        else:
            return "unknown"

    @staticmethod
    def zmap_probe_module_to_port_protocol(probe_module):
        """
        Get a constant representing the port protocol used by the specified Zmap probe module.
        :param probe_module: The Zmap probe module to check.
        :return: A string representing the port protocol used by the specified Zmap probe module.
        """
        if probe_module == "tcp_synscan":
            return "tcp"
        else:
            raise ValueError(
                "Unable to determine port protocol from Zmap probe module %s."
                % (probe_module,)
            )

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
