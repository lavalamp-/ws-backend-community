# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import FilesystemHelper


class BaseParser(object):
    """
    This class serves as a base class for all parser classes used by the Web Sight parsing module.
    Wrappers differ from parsers in that wrappers take in data through their constructor and subsequently
    operate upon that data. Parsers, on the other hand, are responsible for setting up wrappers and extracting
    more advanced information from wrappers.
    """

    # Class Members

    _parse_target = None

    # Instantiation

    def __init__(self, target):
        """
        Initialize this parser object to have a reference to the target that should be parsed, and to set
        up any necessary wrapper classes.
        :param target: The target that should be parsed. The value that this argument can take varies greatly
        and depends on the individual parser implementation.
        """
        self._parse_target = target

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def identifier(self):
        """
        Get a string that contains contextual information about this parser, to be used in the __repr__ of
        each class.
        :return: A string that contains contextual information about this parser, to be used in the __repr__ of
        each class.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def parse_target(self):
        """
        Get a reference to the target object that this parser implementation is meant to process.
        :return: A reference to the target object that this parser implementation is meant to process.
        """
        return self._parse_target

    @property
    def parse_type(self):
        """
        Get a string description of the type of data that this parser is meant to parse.
        :return: A string description of the type of data that this parser is meant to parse.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.identifier)


class BaseFileParser(BaseParser):
    """
    This class serves as a base class for all parsers that rely on parsing the contents of files found
    on the local disk.
    """

    # Class Members

    _file_contents = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def file_contents(self):
        """
        Get the contents of the file that this parser is configured to parse.
        :return: the contents of the file that this parser is configured to parse.
        """
        if self._file_contents is None:
            self._file_contents = FilesystemHelper.get_file_contents(self.file_path)
        return self._file_contents

    @property
    def file_path(self):
        """
        Get the local file path to the file being parsed.
        :return: the local file path to the file being parsed.
        """
        return self.parse_target

    @property
    def identifier(self):
        return self.parse_target

    # Representation and Comparison
