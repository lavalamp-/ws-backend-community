# -*- coding: utf-8 -*-
from __future__ import absolute_import

from datetime import datetime

from .exception import ValidationError
from .wsregex import RegexLib
from .config import ConfigManager

config = ConfigManager.instance()


class ValidationHelper(object):
    """
    A helper class for validating data.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def is_int(to_check):
        """
        Check to see if the input value contains an integer.
        :param to_check: The value to check.
        :return: True if the input value contains an integer, False otherwise.
        """
        try:
            int(to_check)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def is_valid_ipv4_string(to_check):
        """
        Check to see if the contents of to_check represent a valid IPv4 address.
        :param to_check: The value to check.
        :return: A tuple containing (1) True if the value is valid for use as an IPv4 address, False otherwise and
        (2) a list of errors explaining why the value is invalid.
        """
        errors = []
        if not isinstance(to_check, str) and not isinstance(to_check, unicode):
            errors.append(
                "Value was of an unexpected type (%s). Needed unicode or string."
                % (to_check.__class__.__name__,)
            )
        else:
            if not RegexLib.ipv4_address_regex.match(to_check):
                errors.append("Regular expression validation failed.")
        return not bool(errors), errors

    @staticmethod
    def is_valid_mime_string(mime_string):
        """
        Tests the mime_string value to determine whether or not it is a properly-formed MIME
        string.
        :param mime_string: A string containing a MIME content type.
        :return: A list of errors if the MIME string is invalid, or an empty list if it is
        valid.
        """
        errors = []
        if not RegexLib.mime_string_regex.match(mime_string):
            errors.append("mime_string failed to validate against RegexLib.mime_string_regex.")
        return not bool(errors), errors

    @staticmethod
    def is_valid_port(to_check):
        """
        Check to see if the value found within to_check is valid for use as a TCP/UDP/SCTP/etc. port.
        :param to_check: The value to check.
        :return: A tuple containing (1) True if the value is valid for use as a port, False otherwise and
        (2) a list of errors explaining why the value is invalid.
        """
        errors = []
        if not ValidationHelper.is_int(to_check):
            errors.append(
                "The value %s is not an integer."
                % (to_check,)
            )
        else:
            int_val = int(to_check)
            if int_val < 1 or int_val > 65535:
                errors.append(
                    "Port values must be greater than or equal to one, and less than or equal to 65,535. %s is "
                    "not valid."
                    % (int_val,)
                )
        return not bool(errors), errors

    @staticmethod
    def validate_bool(to_check):
        """
        Check to see if the type of the given value is boolean, and raise an error if it is not.
        :param to_check: The value to check.
        :return: None
        """
        ValidationHelper.validate_type(to_check, bool)

    @staticmethod
    def validate_cacheable_type(to_check):
        """
        Validate that to_check is one of the supported argument types for Redis caching.
        :param to_check: The value to test.
        :return: None
        """
        builtin_types = [str, unicode, bool, list, dict, int, datetime, tuple]
        if not any([isinstance(to_check, x) for x in builtin_types]):
            raise ValidationError(
                "Type of %s is not a valid cacheable type."
                % (type(to_check),)
            )

    @staticmethod
    def validate_class(to_check=None, expected_parent_class=None):
        """
        Validate that the given class is a subclass of the given parent class.
        :param to_check: The class to check.
        :param expected_parent_class: The parent class.
        :return: None
        """
        if not issubclass(to_check, expected_parent_class):
            raise ValidationError(
                "Unexpected class received (%s). Expected a subclass of %s."
                % (to_check.__name__, expected_parent_class.__name__)
            )

    @staticmethod
    def validate_es_component_as(to_check):
        """
        Validate that the given value is valid for use as an "as" part of a boolean
        component.
        :param to_check: The value to check.
        :return: None
        """
        ValidationHelper.validate_in(
            to_check=to_check,
            contained_by=["must", "filter", "must_not", "should", "or"]
        )

    @staticmethod
    def validate_es_component_type(to_check):
        """
        Validate that the given object is an instance of BaseElasticsearchComponent.
        :param to_check: The value to check.
        :return: None
        """
        from wselasticsearch.query.components.base import BaseElasticsearchComponent
        ValidationHelper.validate_type(to_check=to_check, expected_class=BaseElasticsearchComponent)

    @staticmethod
    def validate_es_model_class(to_check):
        """
        Validate that the given class is a subclass of BaseElasticsearchModel.
        :param to_check: The class to validate.
        :return: None
        """
        from wselasticsearch.models.base import BaseElasticsearchModel
        ValidationHelper.validate_class(to_check=to_check, expected_parent_class=BaseElasticsearchModel)

    @staticmethod
    def validate_es_model_type(to_check):
        """
        Validate that the given object is an instance of BaseElasticsearchModel.
        :param to_check: The object to validate.
        :return: None
        """
        from wselasticsearch.models.base import BaseElasticsearchModel
        ValidationHelper.validate_type(to_check=to_check, expected_class=BaseElasticsearchModel)

    @staticmethod
    def validate_es_property_index(to_check):
        """
        Validate that the contents of to_check are valid for use as an Elasticsearch index
        type.
        :param to_check: The value to check.
        :return: None
        """
        ValidationHelper.validate_in(
            to_check=to_check,
            contained_by=["analyzed", "not_analyzed", "no"]
        )

    @staticmethod
    def validate_es_query_type(to_check):
        """
        Validate that the given object is an instance of BaseElasticsearchQuery.
        :param to_check: The object to validate.
        :return: None
        """
        from wselasticsearch.query.base import BaseElasticsearchQuery
        ValidationHelper.validate_type(to_check=to_check, expected_class=BaseElasticsearchQuery)

    @staticmethod
    def validate_file_does_not_exist(file_path):
        """
        Validate that a file or directory does not exist at the given path.
        :param file_path: The path to check.
        :return: None
        """
        from .filesystem import FilesystemHelper
        if FilesystemHelper.does_file_exist(file_path=file_path):
            raise ValidationError(
                "File already exists at the path %s."
                % (file_path,)
            )

    @staticmethod
    def validate_file_exists(file_path):
        """
        Validate that a file or directory exists at the given path.
        :param file_path: The path to check.
        :return: None
        """
        from .filesystem import FilesystemHelper
        if not FilesystemHelper.does_file_exist(file_path=file_path):
            raise ValidationError(
                "No file exists at the path %s."
                % (file_path,)
            )

    @staticmethod
    def validate_file_name(file_name):
        """
        Validate that the contents of the given string are valid for use as a file name.
        :param file_name: The string to use as a file name.
        :return: None
        """
        if not RegexLib.file_name_regex.match(file_name):
            raise ValidationError(
                "%s is not a valid file name."
                % (file_name,)
            )

    @staticmethod
    def validate_in(to_check=None, contained_by=None):
        """
        Validate that the given value is contained by the given container.
        :param to_check: The value to check for.
        :param contained_by: The container to check in.
        :return: None
        """
        if to_check not in contained_by:
            raise ValidationError(
                "%s not found in container %s"
                % (to_check, contained_by)
            )

    @staticmethod
    def validate_int(to_check):
        """
        Validate that the contents of to_check represent an integer.
        :param to_check: The value to test.
        :return: None
        """
        if not ValidationHelper.is_int(to_check):
            raise ValidationError(
                "%s is not a valid integer."
                % (to_check,)
            )

    @staticmethod
    def validate_interface_exists(int_name):
        """
        Validate that the given network interface exists on this host.
        :param int_name: The name of the interface to check.
        :return: None
        """
        from .host import HostHelper
        all_interfaces = HostHelper.get_all_network_interfaces()
        ValidationHelper.validate_in(
            to_check=int_name,
            contained_by=all_interfaces,
        )

    @staticmethod
    def validate_ip_address_and_type(address=None, address_type="ipv4"):
        """
        Check to see if the given values represent a valid IP address, and raise an error if they do
        not.
        :param address: The IP address to check.
        :param address_type: The IP address type to check.
        :return: None
        """
        ValidationHelper.validate_ip_address_type(address_type)
        if address_type == "ipv4":
            ValidationHelper.validate_ipv4_address(address)
        elif address_type == "ipv6":
            ValidationHelper.validate_ipv6_address(address)
        else:
            raise ValueError(
                "Not sure how to validate IP address of type %s."
                % (address_type,)
            )

    @staticmethod
    def validate_ipv4_address(to_check):
        """
        Check to see if the contents of to_check are valid for use as an IPv4 address string, and
        raise an error if they are not.
        :param to_check: The value to check.
        :return: None
        """
        is_valid, errors = ValidationHelper.is_valid_ipv4_string(to_check)
        if not is_valid:
            raise ValidationError(
                "Invalid value for IPv4 string (%s). Errors were %s."
                % (to_check, errors)
            )

    @staticmethod
    def validate_ipv4_cidr(to_check):
        """
        Check to see if the contents of to_check are valid for use as an IPv4 CIDR string, and raise
        an error if they are not.
        :param to_check: The value to check.
        :return: None
        """
        if not RegexLib.ipv4_cidr_regex.match(to_check):
            raise ValidationError(
                "String of %s did not pass regular expression test for IPv4 CIDR."
                % (to_check,)
            )

    @staticmethod
    def validate_ipv6_address(to_check):
        """
        Check to see if the contents of to_check are valid for use as an IPv6 address string, and
        raise an error if they are not.
        :param to_check: The value to check.
        :return: None
        """
        raise NotImplementedError("Implement this!")

    @staticmethod
    def validate_ip_address_type(to_check):
        """
        Validate that the contents of to_check represent a valid IP address type.
        :param to_check: The string to check.
        :return: None
        """
        ValidationHelper.validate_in(
            to_check=to_check,
            contained_by=["ipv4", "ipv6"]
        )

    @staticmethod
    def validate_log_level_string(to_check):
        """
        Validate that the given string is a valid logging level.
        :param to_check: The string to check.
        :return: None
        """
        ValidationHelper.validate_in(
            to_check=to_check,
            contained_by=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        )

    @staticmethod
    def validate_mime_string(mime_string):
        """
        Tests to see if mime_string is a valid MIME string, and raises an error if it is not.
        :param mime_string: The string to test.
        :return: None
        """
        is_valid, errors = ValidationHelper.is_valid_mime_string(mime_string)
        if not is_valid:
            raise ValueError(
                "Invalid MIME string (%s). Errors were %s."
                % (mime_string, errors)
            )

    @staticmethod
    def validate_network_mask_length(to_check):
        """
        Check to see if the contents of to_check are valid for use as a network mask length.
        :param to_check: The value to check.
        :return: None
        """
        if to_check > config.rest_max_network_mask_length:
            raise ValidationError(
                "Network mask length of %s exceeds the maximum possible mask length (%s)."
                % (to_check, config.rest_max_network_mask_length)
            )
        if to_check < config.rest_min_network_mask_length:
            raise ValidationError(
                "Network mask length of %s exceeds the minimum possible mask length (%s)."
                % (to_check, config.rest_min_network_mask_length)
            )

    @staticmethod
    def validate_networks_csv_row(csv_row):
        """
        Tests to see if the contents of csv_row are valid for use as a Networks CSV row.
        :param csv_row: A string containing the CSV row contents.
        :return: None
        """
        if not isinstance(csv_row, str):
            raise ValidationError(
                "CSV row (%s) was of an invalid type. Expected string, got %s."
                % (csv_row, type(csv_row))
            )
        if csv_row.count(",") not in [1, 2]:
            raise ValidationError(
                "Got an unexpected number of commas in CSV row. Got %s, expected either two or three."
                % (csv_row.count(","),)
            )
        if csv_row.count(",") == 1:
            name, cidr_string = [x.strip() for x in csv_row.strip().split(",")]
            ValidationHelper.validate_ipv4_cidr(cidr_string)
            address = cidr_string[:cidr_string.find("/")]
            mask_length = int(cidr_string[cidr_string.find("/") + 1:])
        elif csv_row.count(",") == 2:
            name, address, mask_length = [x.strip() for x in csv_row.strip().split(",")]
            ValidationHelper.validate_int(mask_length)
            mask_length = int(mask_length)
        ValidationHelper.validate_ipv4_address(address)
        ValidationHelper.validate_network_mask_length(mask_length)

    @staticmethod
    def validate_nmap_output_type(output_type):
        """
        Validate that the contents of the given string are valid for use as an Nmap output type.
        :param output_type: The string to validate.
        :return: None
        """
        ValidationHelper.validate_in(
            to_check=output_type,
            contained_by=["all", "nmap", "gnmap", "xml"],
        )

    @staticmethod
    def validate_nmap_scan_type(scan_type):
        """
        Validate that the contents of the given string are valid for use as an Nmap scan type.
        :param scan_type: The string to validate.
        :return: None
        """
        ValidationHelper.validate_in(
            to_check=scan_type,
            contained_by=["tcp connect", "tcp syn", "udp"]
        )

    @staticmethod
    def validate_nmap_speed(speed):
        """
        Validate that the contents of the given value are valid for use as an Nmap scanning speed.
        :param speed: The value to check.
        :return: None
        """
        ValidationHelper.validate_int(speed)
        speed = int(speed)
        if speed < 0 or speed > 5:
            raise ValidationError("Nmap speed must be an integer between 0 and 5.")

    @staticmethod
    def validate_non_empty_file(file_path):
        """
        Validate that the referenced file exists and contains data.
        :param file_path: The path to check.
        :return: None
        """
        ValidationHelper.validate_file_exists(file_path)
        from .filesystem import FilesystemHelper
        if not FilesystemHelper.get_file_size(file_path):
            raise ValidationError(
                "File at path %s was empty."
                % (file_path,)
            )

    @staticmethod
    def validate_not_in(to_check=None, contained_by=None):
        """
        Validate that the contents of to_check are not found in the iterabl contained_by.
        :param to_check: The value to check for.
        :param contained_by: The iterable to check in.
        :return: None
        """
        if to_check in contained_by:
            raise ValidationError(
                "Value of %s was found in container %s."
                % (to_check, contained_by)
            )

    @staticmethod
    def validate_port(to_check):
        """
        Validate that the given value is valid for use as a port.
        :param to_check: The value to check.
        :return: None
        """
        is_valid, errors = ValidationHelper.is_valid_port(to_check)
        if not is_valid:
            raise ValidationError(" ".join(errors))

    @staticmethod
    def validate_port_and_protocol(port=None, protocol=None):
        """
        Check to see if the given values are valid for a network port and its related protocol, and raise
        an error if they are not.
        :param port: The port to validate.
        :param protocol: The protocol to validate.
        :return: None
        """
        ValidationHelper.validate_port(port)
        ValidationHelper.validate_transport_type(protocol)

    @staticmethod
    def validate_port_range(start=None, end=None):
        """
        Validate that the contents of start and end represent a valid port range.
        :param start: The start of the port range.
        :param end: The end of the port range.
        :return: None
        """
        ValidationHelper.validate_port(start)
        ValidationHelper.validate_port(end)
        start = int(start)
        end = int(end)
        if start >= end:
            raise ValidationError(
                "Port range must contain at least two ports and end must be larger than start."
            )

    @staticmethod
    def validate_sort_direction(to_check):
        """
        Validate that the contents of to_check are valid for use as a sorting direction.
        :param to_check: The value to check.
        :return: None
        """
        ValidationHelper.validate_in(to_check=to_check, contained_by=["asc", "desc"])

    @staticmethod
    def validate_transport_type(to_check):
        """
        Validate the contents of to_check for use as a network transport layer protocol.
        :param to_check: The value to check.
        :return: None
        """
        ValidationHelper.validate_in(
            to_check=to_check,
            contained_by=["tcp", "udp"],
        )

    @staticmethod
    def validate_type(to_check=None, expected_class=None):
        """
        Validate the the given instance is an instance of the expected class, and raise
        an exception if it is not.
        :param to_check: The instance to check.
        :param expected_class: The class that instance should be an instance of.
        :return: None
        """
        if not isinstance(to_check, expected_class):
            raise ValidationError(
                "Unexpected type received (%s). Expected an instance of %s."
                % (to_check.__class__.__name__, expected_class.__name__)
            )

    @staticmethod
    def validate_zmap_bandwidth(to_check):
        """
        Validate that the value of to_check is\ valid for use as a Zmap bandwidth.
        :param to_check: The string to check.
        :return: None
        """
        errors = []
        if not RegexLib.zmap_bandwidth_regex.match(to_check):
            errors.append(
                "Value of %s did not pass regular expression validation."
                % (to_check,)
            )
        return not bool(errors), errors

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
