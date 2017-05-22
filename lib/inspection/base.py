# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from lib import FilesystemHelper, TempFileMixin

logger = logging.getLogger(__name__)


class BaseInspector(TempFileMixin):
    """
    This class serves as a base class for all classes that perform inspection services for
    the Web Sight platform.
    """

    # Class Members

    _temporary_file_paths = None

    # Instantiation

    def __init__(self):
        """
        Initialize the inspector to ensure that its current internal state reflects a clean
        state.
        """
        super(BaseInspector, self).__init__()

    # Static Methods

    # Class Methods

    # Public Methods

    def clean_up(self):
        """
        Perform any house-keeping necessary to clean up after the inspector once it has finished
        doing its job.
        :return: None
        """
        for file_path in self.temp_file_paths:
            logger.debug(
                "Cleaning up file at path %s."
                % (file_path,)
            )
            if FilesystemHelper.does_file_exist(file_path):
                FilesystemHelper.delete_file(file_path)

    def reset(self):
        """
        Reset the inspector to ensure that any further commands are run without old internal state
        affecting the results.
        :return: None
        """
        self.reset_file_paths()

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def inspection_target(self):
        """
        Get class-specific information about the target that is being inspected by
        this class.
        :return: Class-specific information about the target that is being inspected by
        this class.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)
