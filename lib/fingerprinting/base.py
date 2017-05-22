# -*- coding: utf-8 -*-
from __future__ import absolute_import

import socket
import ssl
import logging

from lib import ElasticsearchableMixin, ConfigManager
from wselasticsearch.models import ServiceFingerprintModel

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


def get_all_supported_fingerprint_services():
    """
    Get a list of strings representing all of the service types that fingerprinting is currently
    available for.
    :return: A list of strings representing all of the service types that fingerprinting is currently
    available for.
    """
    from lib import WsIntrospectionHelper
    fingerprint_classes = WsIntrospectionHelper.get_fingerprinting_classes()
    return [fingerprint_class.get_service_name() for name, fingerprint_class in fingerprint_classes]


class BaseFingerprinter(ElasticsearchableMixin):
    """
    This is a base class for all classes that perform network service fingerprinting.
    """
    
    # Class Members

    _fingerprint_found = False
    _socket = None

    # Instantiation

    def __init__(self, ip_address=None, port=None, protocol=None):
        """
        Initialize the fingerprinter.
        :param ip_address: The IP address where the remote service resides.
        :param port: The port where the remote service resides.
        :param protocol: The protocol to use to connect to the remote protocol.
        """
        self.ip_address = ip_address
        self.port = port
        self.protocol = protocol

    # Static Methods

    # Class Methods

    @classmethod
    def get_mapped_es_model_class(cls):
        from wselasticsearch.models import ServiceFingerprintModel
        return ServiceFingerprintModel

    @classmethod
    def get_service_name(cls):
        """
        Get a string representing the service type that this fingerprinter is configured to
        check for.
        :return: A string representing the service type that this fingerprinter is configured to
        check for.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Public Methods

    def perform_fingerprinting(self):
        """
        Attempt to see if the remote service is running this service type.
        :return: None
        """
        try:
            self._fingerprint_found = self._perform_fingerprinting(self.socket)
        except (socket.error, socket.timeout) as e:
            self._fingerprint_found = False
            logger.warning(
                "Error thrown when attempting to fingerprint service: %s"
                % (e.message,)
            )
        self._close_socket()

    # Protected Methods

    def _close_socket(self):
        """
        Close self.socket if it's currently connected.
        :return: None
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _get_connected_socket(self):
        """
        Create and return a socket to use to communicate with the remote endpoint.
        :return: A socket configured to communicate with the remote endpoint.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _perform_fingerprinting(self, socket):
        """
        Perform the necessary communication with the remote service to determine whether the
        service being tested for exists.
        :param socket: The socket to use for communication with the remote service.
        :return: True if the remote service is running the service this fingerprinting class is
        meant to check for, False otherwise.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def _to_es_model(self):
        return ServiceFingerprintModel(
            fingerprint_name=self.fingerprint_name,
            fingerprint_result=self.fingerprint_found,
            ssl_supported=False,
            ssl_version=None,
        )

    # Private Methods

    # Properties

    @property
    def fingerprint_found(self):
        """
        Get whether or not service fingerprinting determined that the remote service is running
        the service type that this fingerprinter is configured to investigate for.
        :return: whether or not service fingerprinting determined that the remote service is
        running the service type that this fingerprinter is configured to investigate for.
        """
        return self._fingerprint_found

    @property
    def fingerprint_name(self):
        """
        Get the name of the service this fingerprinter is meant to search for.
        :return: the name of the service this fingerprinter is meant to search for.
        """
        return self.__class__.get_service_name()

    @property
    def socket(self):
        """
        Get a socket to use to connect to the remote service.
        :return: a socket to use to connect to the remote service.
        """
        if self._socket is None:
            self._socket = self._get_connected_socket()
        return self._socket

    # Representation and Comparison
    
    def __repr__(self):
        return "<%s - %s:%s (%s) %s>" % (
            self.__class__.__name__,
            self.ip_address,
            self.port,
            self.protocol,
            self.fingerprint_name,
        )


class BaseTcpFingerprinter(BaseFingerprinter):
    """
    A base class for all fingerprinter classes that connect to TCP services without SSL.
    """
    
    # Class Members

    # Instantiation

    def __init__(self, ip_address=None, port=None):
        super(BaseTcpFingerprinter, self).__init__(ip_address=ip_address, port=port, protocol="tcp")

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _close_socket(self):
        if self._socket is not None:
            self._socket.close()

    def _get_connected_socket(self):
        to_return = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        to_return.settimeout(config.fingerprint_socket_timeout)
        to_return.connect((self.ip_address, self.port))
        to_return.settimeout(config.fingerprint_socket_timeout)
        return to_return

    # Private Methods

    # Properties

    # Representation and Comparison


class BaseSslTcpFingerprinter(BaseTcpFingerprinter):
    """
    A base class for all fingerprinter classes that connect to TCP services with SSL.
    """

    # Class Members

    # Instantiation

    def __init__(self, ip_address=None, port=None, ssl_version=ssl.PROTOCOL_TLSv1_2):
        self.ssl_version = ssl_version
        super(BaseSslTcpFingerprinter, self).__init__(ip_address=ip_address, port=port)

    # Static Methods

    # Class Methods

    # Public Methods

    def get_fingerprint_result_record(self, org_uuid=None, scan_uuid=None, service_uuid=None):
        to_return = super(BaseSslTcpFingerprinter, self).get_fingerprint_result_record(
            org_uuid=org_uuid,
            scan_uuid=scan_uuid,
            service_uuid=service_uuid,
        )
        to_return.ssl_supported = True
        to_return.ssl_version = self.ssl_version
        return to_return

    # Protected Methods

    def _get_connected_socket(self):
        base_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        to_return = ssl.wrap_socket(base_socket, ssl_version=getattr(ssl, self.ssl_version))
        to_return.settimeout(config.fingerprint_socket_timeout)
        to_return.connect((self.ip_address, self.port))
        to_return.settimeout(config.fingerprint_socket_timeout)
        return to_return

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s:%s (%s with SSL) %s>" % (
            self.__class__.__name__,
            self.ip_address,
            self.port,
            self.protocol,
            self.fingerprint_name,
        )

