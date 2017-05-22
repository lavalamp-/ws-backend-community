# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework.response import Response


class WsBaseResponse(Response):
    """
     This is the base rest response, subclassed by different responses to return specific information
    """

    # Class Members

    # Instantiation
    def __init__(self, data={}, *args, **kwargs):
        super(WsBaseResponse, self).__init__(*args, **kwargs)
        self.data = data

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
