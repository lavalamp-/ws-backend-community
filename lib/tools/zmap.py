# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from lib import ValidationHelper, ElasticsearchableMixin, FilesystemHelper
from .base import BaseNetworkScannerRunner
from lib.sqlalchemy import ZmapConfig

logger = logging.getLogger(__name__)


class ZmapRunner(BaseNetworkScannerRunner, ElasticsearchableMixin):
    """
    This class serves as a wrapper class for invoking zmap, the Internet-capable network scanner.
    """

    # Class Members

    _bandwidth = None
    _blacklist_file = None
    _default_output_fields = ["saddr", "daddr"]
    _default_probe_module = "tcp_synscan"
    _interface = None
    _output_file = None
    _output_fields = None
    _possible_output_fields = ["saddr", "daddr"]
    _possible_probe_modules = ["tcp_synscan"]
    _probe_module = None
    _target_port = None
    _whitelist_file = None

    # Instantiation

    def __init__(self):
        self._output_fields = self.default_output_fields

    # Static Methods

    # Class Methods

    @classmethod
    def _from_configuration(cls, tool_config):
        to_return = ZmapRunner()
        to_return.bandwidth = tool_config.bandwidth
        return to_return

    @classmethod
    def from_scan_config(cls, scan_config):
        """
        Create and return an instance of this tool runner based on the settings associated with
        the given ScanConfig.
        :param scan_config: The ScanConfig to create a ZmapRunner based off of.
        :return: The newly-created ZmapRunner.
        """
        to_return = ZmapRunner()
        to_return.bandwidth = scan_config.network_scan_bandwidth
        return to_return

    @classmethod
    def get_configuration_class(cls):
        return ZmapConfig

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import ZmapScanResultModel
        return ZmapScanResultModel

    # Public Methods

    def add_output_field(self, to_add):
        """
        Add the specified output field as one of the fields that the Zmap CSV output should include.
        :param to_add: The field to add.
        :return: None
        """
        if to_add not in self.possible_output_fields:
            raise ValueError(
                "ZmapWrapper.add_output_field received an unexpected value (%s). Must be one of %s."
                % (to_add, self.possible_output_fields)
            )
        elif to_add in self.output_fields:
            logger.warning(
                "Attempted to add output field of %s to Zmap output fields, when field is already selected."
                % (to_add,)
            )
        else:
            self._output_fields.append(to_add)

    def get_scanned_networks(self):
        """
        Get a list of CIDR ranges that this Zmap scanner is configured to scan.
        :return: A list of CIDR ranges that this Zmap scanner is configured to scan.
        """
        return FilesystemHelper.get_lines_from_file(self.whitelist_file)

    def limit_bandwidth_by_gbps(self, amount):
        """
        Cap the bandwidth used by the Zmap scanner to the specified amount in gbps.
        :param amount: The amount in gbps to limit the scanner's bandwidth to.
        :return: None
        """
        self.bandwidth = "%sG" % (amount,)

    def limit_bandwidth_by_kbps(self, amount):
        """
        Cap the bandwidth used by the Zmap scanner to the specified amount in kbps.
        :param amount: The amount in kbps to limit the scanner's bandwidth to.
        :return: None
        """
        self.bandwidth = "%sK" % (amount,)

    def limit_bandwidth_by_mbps(self, amount):
        """
        Cap the bandwidth used by the Zmap scanner to the specified amount in mbps.
        :param amount: The amount in mbps to limit the scanner's bandwidth to.
        :return: None
        """
        self.bandwidth = "%sM" % (amount,)

    def reset(self):
        """
        Reset this ZmapWrapper to its default configuration.
        :return: None
        """
        super(ZmapRunner, self).reset()
        self._bandwidth = None
        self._blacklist_file = None
        self._interface = None
        self._output_file = None
        self._probe_module = self.default_probe_module
        self._target_port = None
        self._whitelist_file = None
        self.reset_output_fields()

    def reset_output_fields(self):
        """
        Reset the CSV output fields to their defaults.
        :return: None
        """
        self._output_fields = [x for x in self.default_output_fields]

    # Protected Methods

    def _get_command_line_flags(self):
        to_return = []
        if self.bandwidth is not None:
            to_return.append(("-B", self.bandwidth))
        if self.blacklist_file is not None:
            to_return.append(("-b", self.blacklist_file))
        if self.whitelist_file is not None:
            to_return.append(("-w", self.whitelist_file))
        if self.output_file is not None:
            to_return.append(("-o", self.output_file))
        if self.target_port is not None:
            to_return.append(("-p", self.target_port))
        if self.interface is not None:
            to_return.append(("-i", self.interface))
        if self.output_fields is not None:
            to_return.append(("-f", ",".join(self.output_fields)))
        if self.probe_module is not None:
            to_return.append(("-M", self.probe_module))
        return to_return

    def _get_results_parser(self):
        from lib.parsing import ZmapCsvParser
        return ZmapCsvParser(self.output_file)

    def _is_tool_ready(self):
        errors = []
        if self.output_file is None:
            errors.append("No output file specified.")
        if self.target_port is None:
            errors.append("No target port specified.")
        if self.whitelist_file is None:
            errors.append("No whitelist file specified.")
        return not bool(errors), errors

    def _prepare_pre_run(self):
        FilesystemHelper.touch(self.output_file)

    def _set_to_scan_tcp(self):
        self.probe_module = "tcp_synscan"

    def _to_es_model(self):
        from wselasticsearch.models import ZmapScanResultModel
        results_parser = self.get_results_parser()
        return ZmapScanResultModel(
            start_time=self.start_time,
            end_time=self.end_time,
            port=self.target_port,
            discovered_endpoints=results_parser.get_live_ips(),
            cmd_line=self.command_line,
            scanned_networks=self.get_scanned_networks(),
        )

    # Private Methods

    # Properties

    @property
    def bandwidth(self):
        """
        Get the maximum amount of bandwidth that this scan should consume.
        :return: The maximum amount of bandwidth that this scan should consume.
        """
        return self._bandwidth

    @bandwidth.setter
    def bandwidth(self, new_value):
        """
        Set the maximum amount of bandwidth that this scan should consume.
        :param new_value: The maximum amount of bandwidth that this scan should consume.
        :return: None
        """
        ValidationHelper.validate_zmap_bandwidth(new_value)
        self._bandwidth = new_value

    @property
    def blacklist_file(self):
        """
        Get a file path to a file containing networks that should be excluded from the scan.
        :return: A file path to a file containing networks that should be excluded from the scan.
        """
        return self._blacklist_file

    @blacklist_file.setter
    def blacklist_file(self, new_value):
        """
        Set the value of the file path to a file containing networks that should be excluded from
        the scan.
        :param new_value: The local file path to the blacklist file.
        :return: None
        """
        if new_value is not None:
            ValidationHelper.validate_file_exists(new_value)
        self._blacklist_file = new_value

    @property
    def command(self):
        return "zmap"

    @property
    def default_output_fields(self):
        """
        Get a list of strings representing the output fields that the Zmap scanner will spit out by
        default.
        :return: A list of strings representing the output fields that the Zmap scanner will spit out by
        default.
        """
        return self._default_output_fields

    @property
    def default_probe_module(self):
        """
        Get a string representing the default probe module that Zmap should use.
        :return: a string representing the default probe module that Zmap should use.
        """
        return self._default_probe_module

    @property
    def interface(self):
        """
        Get a string describing the network interface that this scanner is configured to use.
        :return: A string describing the network interface that this scanner is configured to use.
        """
        return self._interface

    @interface.setter
    def interface(self, new_value):
        """
        Set the interface that Zmap should use for scanning.
        :param new_value: A string describing the interface that Zmap should use for scanning.
        :return: None
        """
        if new_value is not None:
            ValidationHelper.validate_interface_exists(new_value)
        self._interface = new_value

    @property
    def output_file(self):
        """
        Get the file path where the results of this scan should be written to.
        :return: The file path where the results of this scan should be written to.
        """
        return self._output_file

    @output_file.setter
    def output_file(self, new_value):
        """
        Set the value of self._output_file.
        :param new_value: The new value to set self._output_file to.
        :return: None
        """
        if new_value is not None:
            ValidationHelper.validate_file_does_not_exist(new_value)
        self._output_file = new_value

    @property
    def output_fields(self):
        """
        Get the list of fields that Zmap will spit out in the CSV output file.
        :return: The list of fields that Zmap will spit out in the CSV output file.
        """
        return self._output_fields

    @property
    def possible_output_fields(self):
        """
        Get a list of strings representing all of the possible fields that Zmap CSV files can contain.
        :return: A list of strings representing all of the possible fields that Zmap CSV files can contain.
        """
        return self._possible_output_fields

    @property
    def possible_probe_modules(self):
        """
        Get a list of strings representing the various probe modules that Zmap can use.
        :return: a list of strings representing the various probe modules that Zmap can use.
        """
        return self._possible_probe_modules

    @property
    def probe_module(self):
        """
        Get a string representing the probe module that Zmap should use when invoked.
        :return: a string representing the probe module that Zmap should use when invoked.
        """
        return self._probe_module

    @probe_module.setter
    def probe_module(self, new_value):
        """
        Set the probe module that Zmap should use to connect to the referenced endpoints.
        :param new_value: A string representing the probe module that Zmap should use to connect
        to the referenced endpoints.
        :return: None
        """
        ValidationHelper.validate_in(
            to_check=new_value,
            contained_by=self.possible_probe_modules,
        )
        self._probe_module = new_value

    @property
    def target_port(self):
        """
        Get the port that should be scanned.
        :return: The port that should be scanned.
        """
        return self._target_port

    @target_port.setter
    def target_port(self, new_value):
        """
        Set the port that should be scanned.
        :param new_value: The value to set as the port to scan.
        :return: None
        """
        ValidationHelper.validate_port(new_value)
        self._target_port = int(new_value)

    @property
    def tool_name(self):
        return "Zmap"

    @property
    def whitelist_file(self):
        """
        Get a file path to a file containing the network ranges to scan.
        :return: A file path to a file containing the network ranges to scan.
        """
        return self._whitelist_file

    @whitelist_file.setter
    def whitelist_file(self, new_value):
        """
        Set the file path pointing to a file containing the network ranges to scan.
        :param new_value: The new value to set self._whitelist_file to.
        :return: None
        """
        if new_value is not None:
            ValidationHelper.validate_file_exists(new_value)
        self._whitelist_file = new_value

    # Representation and Comparison
