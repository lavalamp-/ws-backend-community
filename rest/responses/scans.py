# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import WsBaseResponse


class WsScanConfigValidityResponse(WsBaseResponse):
    """
    This is the response used to provide information about the validity of a ScanConfig
    object.
    """

    def __init__(self, scan_config=None, *args, **kwargs):
        super(WsScanConfigValidityResponse, self).__init__(*args, **kwargs)
        self.data = {
            "is_valid": scan_config.is_ready_to_place,
            "errors": scan_config.get_ready_errors(),
        }
