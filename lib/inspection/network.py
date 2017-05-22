# -*- coding: utf-8 -*-
from __future__ import absolute_import

import socket
import ssl
import OpenSSL
import logging

from .base import BaseInspector
from lib import ValidationHelper, ConfigManager, ConversionHelper
from .exception import SslCertificateRetrievalFailedError

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


class PortInspector(BaseInspector):
    """
    This class contains methods for inspecting the state of a host's port.
    """

    # Class Members

    _address = None
    _address_type = None
    _port = None
    _protocol = None

    # Instantiation

    def __init__(self, address=None, address_type="ipv4", port=None, protocol=None):
        """
        Initialize this PortInspector to maintain references to the data necessary to
        interact with a remote port.
        :param address: The IP address.
        :param address_type: The IP address type.
        :param port: The port to inspect.
        :param protocol: The protocol to use to inspect the port.
        """
        ValidationHelper.validate_ip_address_and_type(address=address, address_type=address_type)
        ValidationHelper.validate_port_and_protocol(port=port, protocol=protocol)
        self._address = address
        self._address_type = address_type
        self._port = port
        self._protocol = protocol
        super(PortInspector, self).__init__()

    # Static Methods

    # Class Methods

    # Public Methods

    def check_if_open(self, connect_timeout=config.inspection_socket_connect_timeout):
        """
        Check to see if the remote port is open.
        :param connect_timeout: The amount of time that the connection establishment should wait
        on.
        :return: True if the remote port is open, False otherwise.
        """
        if self.is_tcp_protocol:
            connected = None
            try:
                connected = self.__get_plain_tcp_socket(connect_timeout=connect_timeout)
                return True
            except socket.error:
                return False
            finally:
                if connected is not None:
                    connected.close()
        elif self.is_udp_protocol:
            raise NotImplementedError("This has not been implemented yet.")
        else:
            raise ValueError("No logic for handling protocol type of %s." % (self.protocol,))

    def check_ssl_support(
            self,
            connect_timeout=config.inspection_socket_connect_timeout,
            ssl_version=None,
            ssl_version_name=None,
    ):
        """
        Attempt to connect to the remote service using an SSL wrapped connection with the specified version.
        :param connect_timeout: The amount of time in milliseconds to wait before timing the connection
        out.
        :param ssl_version: The SSL version to open the connection with. Note that only this or ssl_version_name
        should be supplied as arguments.
        :param ssl_version_name: The SSL version name to open the connection with. Note that only this or
        ssl_version should be supplied as arguments.
        :return: True if the SSL connection fails, False otherwise.
        """
        if ssl_version is not None or ssl_version_name is not None:
            ssl_version = ssl_version if ssl_version else getattr(ssl, ssl_version_name)
        ssl_sock = None
        try:
            ssl_sock = self.get_connected_socket(
                include_ssl=True,
                connect_timeout=connect_timeout,
                ssl_version=ssl_version,
            )
            return True
        except (ssl.SSLError, socket.error) as e:
            return False
        finally:
            if ssl_sock is not None:
                ssl_sock.close()

    def get_connected_socket(self, include_ssl=False, connect_timeout=config.inspection_socket_connect_timeout, ssl_version=None):
        """
        Get a Python socket that is connected to the remote service and ready for send commands.
        :param include_ssl: Whether or not to wrap the socket in SSL.
        :param connect_timeout: The amount of time in milliseconds to wait before timing the connection
        out.
        :param ssl_version: The SSL version to open the connection with.
        :return: A Python Socket that is connected to the remote service.
        """
        if ssl_version and not include_ssl:
            raise ValueError(
                "ssl_version suppled to __get_connected_socket when include_ssl was False."
            )
        if include_ssl:
            if self.is_tcp_protocol:
                return self.__get_ssl_tcp_socket(connect_timeout=connect_timeout, ssl_version=ssl_version)
            elif self.is_udp_protocol:
                raise ValueError("SSL over UDP? Are you mad?")
            else:
                raise ValueError("No logic for handling service type of %s." % (self.protocol,))
        else:
            if self.is_tcp_protocol:
                return self.__get_plain_tcp_socket(connect_timeout=connect_timeout)
            elif self.is_udp_protocol:
                return self.__get_plain_udp_socket(connect_timeout=connect_timeout)
            else:
                raise ValueError("No logic for handling service type of %s." % (self.protocol,))

    def get_ssl_certificate(self, ssl_version=None):
        """
        Get an OpenSSL cryptographic PEM certificate from the endpoint using the specified SSL version.
        :param ssl_version: The SSL version to connect with. If None, then let OpenSSL negotiate which
        protocol to use.
        :return: A tuple containing (1) the certificate string and (2) an OpenSSL cryptographic PEM
        certificate from the endpoint.
        """

        try:
            if ssl_version is not None:
                cert = ssl.get_server_certificate((self.address, self.port), ssl_version=getattr(ssl, ssl_version))
            else:
                cert = ssl.get_server_certificate((self.address, self.port))
            return cert, OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        except ssl.SSLError as e:
            raise SslCertificateRetrievalFailedError(
                message="SSL error thrown when retrieving SSL certificate: %s." % (e,)
            )

    # Protected Methods

    # Private Methods

    def __get_plain_tcp_socket(self, connect_timeout=config.inspection_socket_connect_timeout):
        """
        Get a TCP Python socket that is connected to the remote service.
        :param connect_timeout: The amount of time in milliseconds to wait before timing the connection
        out.
        :return: A TCP Python socket that is connected to the remote service.
        """
        to_return = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        to_return.settimeout(connect_timeout)
        to_return.connect((self.address, self.port))
        return to_return

    def __get_plain_udp_socket(self, connect_timeout=config.inspection_socket_connect_timeout):
        """
        Get a UDP Python socket that is connected to the remote service.
        :param connect_timeout: The amount of time in milliseconds to wait before timing the connection
        out.
        :return: A UDP Python socket that is connected to the remote service.
        """
        to_return = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        to_return.settimeout(connect_timeout)
        return to_return

    def __get_ssl_tcp_socket(self, connect_timeout=config.inspection_socket_connect_timeout, ssl_version=None):
        """
        Get an SSL-wrapped TCP socket that is connected to the remote service.
        :param connect_timeout: The amount of time in milliseconds to wait before timing the connection
        out.
        :param ssl_version: The SSL version to open the connection with.
        :return: An SSL-wrapped TCP socket that is connected to the remote service.
        """
        if ssl_version and ssl_version not in self.available_ssl_protocols:
            raise ValueError(
                "Unexpected ssl_version value received in __get_ssl_tcp_socket. Got %s, expected %s."
                % (ssl_version, self.available_ssl_protocols)
            )
        plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_socket = ssl.wrap_socket(plain_socket, ssl_version=ssl_version) \
            if ssl_version is not None \
            else ssl.wrap_socket(plain_socket)
        ssl_socket.settimeout(connect_timeout)
        ssl_socket.connect((self.address, self.port))
        return ssl_socket

    # Properties

    @property
    def available_ssl_protocols(self):
        """
        Get a list of the valid values that can be supplied to SSL socket establishment.
        :return: A list of the valid values that can be supplied to SSL socket establishment.
        """
        return sorted(ssl._PROTOCOL_NAMES.keys())

    @property
    def available_ssl_protocol_names(self):
        """
        Get a list of strings depicting the different SSL protocols available on the requesting
        machine.
        :return: A list of strings depicting the different SSL protocols available on the requesting
        machine.
        """
        return ssl._PROTOCOL_NAMES.values()

    @property
    def address(self):
        """
        Get the IP address where the port resides.
        :return: the IP address where the port resides.
        """
        return self._address

    @property
    def address_type(self):
        """
        Get the type of the IP address where the port resides.
        :return: the type of the IP address where the port resides.
        """
        return self._address_type

    @property
    def default_ssl_protocol(self):
        """
        Get the value to supply to the default SSL connection functionality.
        :return: The value to supply to the default SSL connection functionality.
        """
        return self.available_ssl_protocols[-1]

    @property
    def is_tcp_protocol(self):
        """
        Get whether or not self.protocol refers to the TCP protocol.
        :return: whether or not self.protocol refers to the TCP protocol
        """
        return self.protocol == "tcp"

    @property
    def is_udp_protocol(self):
        """
        Get whether or not self.protocol refers to the UDP protocol.
        :return: whether or not self.protocol refers to the UDP protocol.
        """
        return self.protocol == "udp"

    @property
    def port(self):
        """
        Get the port number to connect to.
        :return: the port number to connect to.
        """
        return self._port

    @property
    def protocol(self):
        """
        Get the port protocol that should be used to connect to the remote port.
        :return: the port protocol that should be used to connect to the remote port.
        """
        return self._protocol

    # Representation and Comparison
