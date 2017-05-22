# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework.response import Response


class NetworksUploadResponse(Response):
    """
    Documentation for NetworksUploadResponse.
    """

    # Class Members

    # Instantiation

    def __init__(self, new_networks=None, skipped=None, blacklisted=None, errored=None, *args, **kwargs):
        super(NetworksUploadResponse, self).__init__(*args, **kwargs)
        self.data = {
            "new_networks": len(new_networks),
            "skipped": len(skipped),
            "blacklisted": len(blacklisted),
            "errored": len(errored),
        }

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class DomainsUploadResponse(Response):
    """
    This is a response for returning information to end users about the success of a domain file
    upload.
    """

    def __init__(self, new_domains=0, skipped=0, errored=0, batch_required=False, *args, **kwargs):
        super(DomainsUploadResponse, self).__init__(*args, **kwargs)
        self.data = {
            "new_domains": new_domains,
            "skipped": skipped,
            "errored": errored,
            "batch_required": batch_required,
        }
