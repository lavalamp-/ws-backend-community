# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import HashHelper
from lib import FilesystemHelper


class BaseWrapper(object):
    """
    This class serves as a base class for all wrapper classes used by the Web Sight parsing module.
    Wrappers differ from parsers in that wrappers take in data through their constructor and subsequently
    operate upon that data. Parsers, on the other hand, are responsible for setting up wrappers and extracting
    more advanced information from wrappers.
    """

    # Class Members

    _wrapped_data = None

    # Instantiation

    def __init__(self, to_wrap):
        """
        Initialize this wrapper class to maintain a reference to the data it is meant to process, and
        to perform any initial data processing.
        :param to_wrap: The data that this wrapper class is meant to process. Note that this should be a
        basic Python type such as a string or a binary blob.
        """
        self._wrapped_data = to_wrap
        self._validate_data()
        self._process_data()

    # Static Methods

    # Class Methods

    @classmethod
    def from_file(cls, file_path):
        """
        Create an instance of this wrapper class based on the contents of a given file.
        :param file_path: The file path to read data from.
        :return: An instance of this wrapper class wrapping the contents of the given file.
        """
        file_contents = FilesystemHelper.get_file_contents(file_path).strip()
        return cls(file_contents)

    # Public Methods

    def get_hash(self):
        """
        Get an MD5 hash that represents the data contained within this wrapper class. Note that
        subclasses can override self._get_hashable_data to specify what data should be hashed.
        :return: An MD5 hash that represents the data contained within this wrapper class.
        """
        return HashHelper.md5_digest(self._get_hashable_data())

    # Protected Methods

    def _get_hashable_data(self):
        """
        Get the data that self.get_hash should calculate a hash upon.
        :return: The data that self.get_hash should calculate a hash upon.
        """
        return self.wrapped_data

    def _process_data(self):
        """
        Process the contents of self._wrapped_data to bootstrap the wrapper class. This does not need
        to be done, but enables subclasses to hook into the initialization process to fill out the
        class.
        :return: None
        """
        pass

    def _validate_data(self):
        """
        Check the contents of the wrapped data to ensure that the data is valid for use by this wrapper
        class. This method should raise a ValidationError if the contents of self.wrapped_data are invalid.
        :return: None
        """
        pass

    # Private Methods

    # Properties

    @property
    def wrapped_data(self):
        """
        Get the data that this wrapper object is operating upon.
        :return: The data that this wrapper object is operating upon.
        """
        return self._wrapped_data

    @property
    def wrapped_type(self):
        """
        Get a string description of the type of data that this wrapper class is meant to process.
        :return: A string description of the type of data that this wrapper class is meant to process.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.wrapped_type)
