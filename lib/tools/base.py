# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
from datetime import datetime
import subprocess

from lib import PathHelper
from lib import TempFileMixin
from lib import ValidationHelper
from .exception import ToolConfigNotFoundError, ToolResultsNotReadyError, ToolNotFoundError, \
    ToolNotReadyError, NotSupportedError

logger = logging.getLogger(__name__)


class BaseToolRunner(object):
    """
    A base class for classes that wrap command line tools. This class can be seen as a stop
    gap until we write Python bindings for the relevant tools.
    """

    # Class Members

    _end_time = None
    _has_run = False
    _start_time = None

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def _from_configuration(cls, tool_config):
        """
        Create and return an instance of cls configured by the contents of tool_config.
        :param tool_config: A ToolConfig-derived class that contains configuration data related
        to the wrapped tool.
        :return: A newly-created instance of cls configured by the contents of tool_config.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @classmethod
    def get_configuration_class(cls):
        """
        Get the model configuration class that this wrapper can be instantiated based upon.
        :return: The model configuration class that this wrapper can be instantiated based upon.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @classmethod
    def from_configuration(cls, tool_config):
        """
        Create and return an instance of this class that is configured based on the contents of
        tool_config.
        :param tool_config: An instance of a ToolConfig-derived class that contains configuration
        information pertaining to the wrapped tool.
        :return: A new instance of cls configured based on the contents of tool_config.
        """
        if not isinstance(tool_config, cls.get_configuration_class()):
            raise TypeError(
                "%s cannot be configured by a %s object (requires %s instead)."
                % (cls.__name__, tool_config.__class__.__name__, cls.get_configuration_class().__name__)
            )
        return cls._from_configuration(tool_config)

    @classmethod
    def from_default_configuration(cls, db_session):
        """
        Create and return an instance of this class that is configured based on the default
        configuration found within the queried database.
        :param db_session: A SQLAlchemy session to use to query a database.
        :return: A new instance of cls configured based on the contents of the default tool config
        as found in the configured database.
        """
        config_class = cls.get_configuration_class()
        tool_config = db_session.query(config_class).filter(config_class.name == u"default").one_or_none()
        if tool_config is None:
            raise ToolConfigNotFoundError(
                message="No default configuration was found for class %s." % (config_class.__name__,)
            )
        return cls.from_configuration(tool_config)

    # Public Methods

    def get_results_parser(self):
        """
        Get a parser object that is configured to parse the results of running the wrapped tool. Note
        that this should only be called after the tool has successfully been run.
        :return: A parser object that is configured to parse the results of running the wrapped tool.
        """
        if not self.has_run:
            raise ToolResultsNotReadyError()
        return self._get_results_parser()

    def reset(self):
        self._end_time = None
        self._has_run = False
        self._start_time = None

    def run(self):
        """
        Run the tool to inspect the inspection target.
        :return: None
        """
        if not self.__does_tool_exist():
            raise ToolNotFoundError()
        is_ready, errors = self._is_tool_ready()
        if not is_ready:
            raise ToolNotReadyError(message=" ".join(errors))
        else:
            self._prepare_pre_run()
            self._start_time = datetime.now()
            self.__run()
            self._end_time = datetime.now()
            self._has_run = True

    # Protected Methods

    def _get_command_line_flags(self):
        """
        Get a list of command line flags to pass to the wrapped tool to handle the tool invocation
        correctly.
        :return: A list of tuples containing command line flags to pass to the wrapped tool.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _get_results_parser(self):
        """
        Get a parser object that is set up to parse the results of running the wrapped tool.
        :return: A parser object that is set up to parse the results of running the wrapped tool.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _is_tool_ready(self):
        """
        Check to see whether or not the wrapped tool is ready to be run, based on the current configuration
        of this inspector wrapper.
        :return: A tuple containing (1) True if the tool and the configuration held within self is ready,
        False otherwise and (2) a list of errors describing why the tool is not ready.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _prepare_pre_run(self):
        """
        Perform any housekeeping necessary before the external tool is invoked.
        :return: None
        """
        pass

    # Private Methods

    def __does_tool_exist(self):
        """
        Check to see whether or not the tool this wrapper is meant to wrap actually exists on the
        underlying host.
        :return: True if the tool exists on the underlying host, False otherwise.
        """
        return PathHelper.is_executable_in_path(self.command)

    def __get_popen_list(self):
        """
        Get a list containing the command name as well as the arguments to pass to invocation of the
        wrapped tool.
        :return: A list containing the command name as well as the arguments to pass to invocation of the
        wrapped tool.
        """
        to_return = [self.command]
        for option_tuple in self._get_command_line_flags():
            for entry in option_tuple:
                to_return.append(str(entry))
        return to_return

    def __run(self):
        """
        Invoke the actual command and block until the command has finished.
        :return: The process return code.
        """
        popen_list = self.__get_popen_list()
        process = subprocess.Popen(
            popen_list,
            shell=False,
        )
        out, err = process.communicate()
        logger.debug(
            "Standard out: %s."
            % (out,)
        )
        logger.debug(
            "Standard error: %s."
            % (err,)
        )
        return process.returncode

    # Properties

    @property
    def command(self):
        """
        Get the name of the command that is being invoked (ie: nmap, zmap, rabbitmq-ctl, etc).
        :return: The name of the command that is being invoked.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def command_line(self):
        """
        Get the command line invocation that will be executed upon calling self.run.
        :return: The command line invocation that will be executed upon calling self.run.
        """
        return " ".join(self.__get_popen_list())

    @property
    def end_time(self):
        """
        Get the time at which the underlying tool invocation completed.
        :return: The time at which the underlying tool invocation completed.
        """
        return self._end_time

    @property
    def has_run(self):
        """
        Get whether or not the underlying tool has been invoked in its current configuration.
        :return: True if the underlying tool has been invoked in its current configuration, False otherwise.
        """
        return self._has_run

    @property
    def start_time(self):
        """
        Get the time at which the underlying tool was invoked.
        :return: The time at which the underlying tool was invoked.
        """
        return self._start_time

    @property
    def tool_name(self):
        """
        Get a string representing the name of the tool that this wrapper wraps.
        :return: A string representing the name of the tool that this wrapper wraps.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.command_line)


class BaseNetworkScannerRunner(BaseToolRunner):
    """
    This is a base class for wrapper classes that wrap tools which can scan networks for open services.
    """

    # Class Members

    _protocol = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def reset(self):
        super(BaseNetworkScannerRunner, self).reset()
        self._protocol = None

    def set_scan_protocol(self, protocol):
        """
        Set the protocol that should be used to scan the referenced endpoints.
        :param protocol: The protocol to use to scan the referenced endpoints.
        :return: None
        """
        ValidationHelper.validate_transport_type(protocol)
        if protocol == "tcp":
            self._set_to_scan_tcp()
        elif protocol == "udp":
            self._set_to_scan_udp()
        else:
            raise ValueError(
                "%s does not know how to scan for protocol %s."
                % (self.__class__.__name__, protocol)
            )

    # Protected Methods

    def _set_to_scan_udp(self):
        """
        Configure the wrapper class to scan for UDP services.
        :return: None
        """
        raise NotSupportedError(message="Tool not configured to support UDP scanning!")

    def _set_to_scan_tcp(self):
        """
        Configure the wrapper class to scan for TCP services.
        :return: None
        """
        raise NotSupportedError(message="Tool not configured to support TCP scanning!")

    # Private Methods

    # Properties

    @property
    def protocol(self):
        """
        Get the port protocol that the tool is scanning for.
        :return: the port protocol that the tool is scanning for.
        """
        return self._protocol

    # Representation and Comparison
