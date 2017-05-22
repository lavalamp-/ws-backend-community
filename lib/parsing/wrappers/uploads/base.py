# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..base import BaseWrapper


class BaseUploadWrapper(BaseWrapper):
    """
    This is a base class for all wrapper classes that are used for parsing files uploaded by
    users.
    """

    @classmethod
    def from_uploaded_file(cls, uploaded_file):
        """
        Create and return an instance of this class based on the contents of the given file uploaded through
        the Django rest framework.
        :param uploaded_file: The uploaded file to process.
        :return: An instance of a NetworksCsvWrapper wrapping the contents of the given uploaded file.
        """
        return cls(uploaded_file.file.read())
