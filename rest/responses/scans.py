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


class WsQuickScanResponse(WsBaseResponse):
    """
    This is the response used to provide information about the results of attempting a quick scan
    invocation.
    """

    def __init__(
            self,
            order_uuid=None,
            was_successful=True,
            domains=[],
            networks=[],
            skipped=[],
            description=None,
            *args,
            **kwargs
    ):
        super(WsQuickScanResponse, self).__init__(*args, **kwargs)
        if was_successful:
            self.status_code = 201
        else:
            self.status_code = 400
        self.data = {
            "order_uuid": order_uuid,
            "domains": domains,
            "networks": networks,
            "skipped": skipped,
            "result": description,
        }
