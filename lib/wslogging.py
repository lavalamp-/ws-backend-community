# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
import logging.handlers

from .config import ConfigManager
from .filesystem import FilesystemHelper

config = ConfigManager.instance()


class WsLogFormatter(logging.Formatter):
    """
    This class is the log formatter for all logging done by Web Sight.
    """

    # Class Members

    CRITICAL = "%(asctime)s [CRITICAL] - %(message)s"
    DATE_FORMAT = "[%m/%d/%y %H:%M:%S]"
    DEBUG = "%(asctime)s [DEBUG] - %(message)s"
    ERROR = "%(asctime)s [ERROR] - %(message)s"
    INFO = "%(asctime)s [INFO] - %(message)s"
    WARNING = "%(asctime)s [WARNING] - %(message)s"

    # Instantiation

    def __init__(self):
        super(WsLogFormatter, self).__init__(datefmt=self.DATE_FORMAT)

    # Static Methods

    # Class Methods

    # Public Methods

    def format(self, record):
        if record.levelno == logging.CRITICAL:
            self._fmt = WsLogFormatter.CRITICAL
        elif record.levelno == logging.ERROR:
            self._fmt = WsLogFormatter.ERROR
        elif record.levelno == logging.WARNING:
            self._fmt = WsLogFormatter.WARNING
        elif record.levelno == logging.INFO:
            self._fmt = WsLogFormatter.INFO
        elif record.levelno == logging.DEBUG:
            self._fmt = WsLogFormatter.DEBUG
        return super(WsLogFormatter, self).format(record)

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


def configure_logger(logger=None, level=None, file_path=None):
    """
    Configure the given logger to emit at the given level.
    :param logger: The logger to configure.
    :param level: The level to configure the logger at.
    :param file_path: The file path to where logged data should be stored.
    :return: None
    """
    if not FilesystemHelper.does_directory_exist(config.log_directory):
        FilesystemHelper.create_directories(config.log_directory)
    logger.setLevel(level)
    handler = logging.handlers.RotatingFileHandler(
        file_path,
        maxBytes=config.log_max_bytes,
        backupCount=config.log_max_files,
    )
    handler.setFormatter(WsLogFormatter())
    logger.addHandler(handler)


def initialize_lib_logger(logger):
    """
    Initializes all necessary variables for the logger used by all operations within the DataHound
    library module.
    :param logger: The logger to configure.
    :return: None
    """
    configure_logger(logger=logger, level=config.log_base_level, file_path=config.log_base_file_path)


def initialize_tasknode_logger(logger):
    """
    Initializes all necessary variables for the logger used by the tasknode module.
    :param logger: The logger to configure.
    :return: None
    """
    configure_logger(logger=logger, level=config.log_task_level, file_path=config.log_task_file_path)


def initialize_global_error_logger(logger):
    """
    Initializes all necessary variables for the global logger to log errors to a separate file.
    :param logger: The logger to configure.
    :return: None
    """
    configure_logger(logger=logger, level=logging.ERROR, file_path=config.log_error_file_path)
