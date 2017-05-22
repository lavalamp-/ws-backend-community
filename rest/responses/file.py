# -*- coding: utf-8 -*-
from __future__ import absolute_import

from django.core.files.base import ContentFile
from django.http import HttpResponse


class WsFileResponse(HttpResponse):
    """
    This is a response class for handling returning the contents of a file.
    """

    # Class Members

    # Instantiation

    def __init__(self, file_contents=None, content_type=None, file_name=None, *args, **kwargs):
        super(WsFileResponse, self).__init__(*args, **kwargs)
        self.content = ContentFile(file_contents)
        self["Content-Disposition"] = "attachment; filename=%s" % (file_name,)
        self["Content-Type"] = content_type

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
