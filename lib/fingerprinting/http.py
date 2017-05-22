# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseTcpFingerprinter, BaseSslTcpFingerprinter


class HttpFingerprinter(BaseTcpFingerprinter):
    """
    A fingerprinter class for determining whether a remote service is running HTTP.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_service_name(cls):
        return "http"

    # Public Methods

    # Protected Methods

    def _perform_fingerprinting(self, socket):
        socket.send("GET / HTTP/1.1\r\n\r\n")
        response = socket.recv(1024)
        return response.startswith("HTTP/")

    # Private Methods

    # Properties

    # Representation and Comparison


class HttpsFingerprinter(BaseSslTcpFingerprinter):
    """
    A fingerprinter class for determining whether a remote service is running HTTPS.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    @classmethod
    def get_service_name(cls):
        return "https"

    # Public Methods

    # Protected Methods

    def _perform_fingerprinting(self, socket):
        socket.send("GET / HTTP/1.1\r\n\r\n")
        response = socket.recv(1024)
        return response.startswith("HTTP/")

    # Private Methods

    # Properties

    # Representation and Comparison
