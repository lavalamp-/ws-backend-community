# -*- coding: utf-8 -*-
from __future__ import absolute_import

from requests.adapters import HTTPAdapter, select_proxy, prepend_scheme_if_needed, DEFAULT_POOLBLOCK
from requests.packages.urllib3 import HTTPSConnectionPool, PoolManager
import requests
from requests.packages.urllib3.connection import VerifiedHTTPSConnection, HTTPSConnection

from ..base import BaseInspector
from lib.parsing import UrlWrapper, RequestsTransactionWrapper
from lib import ConfigManager

config = ConfigManager.instance()


class WebSightVerifiedHTTPSConnection(VerifiedHTTPSConnection):
    """
    This is a custom HTTPS connection class that fills out SNI requests based on a set hostname
    instead of the requested url.
    """

    def __init__(self, request_hostname=None, *args, **kwargs):
        self._hostname = request_hostname
        self._host = None
        self._first_host = None
        super(WebSightVerifiedHTTPSConnection, self).__init__(*args, **kwargs)

    def _new_conn(self):
        """
        This is a super-hacky way to do this, as the connection is established based on self.host and
        the SNI name is populated by self.host as well. As such we need to plug self.host when the
        connection is being created and then replace it with the hostname we want to be submitted
        during SNI setup.
        :return: A connection.
        """
        if self.hostname is not None:
            self.host = self.first_host
            to_return = super(WebSightVerifiedHTTPSConnection, self)._new_conn()
            self.host = self.hostname
            return to_return
        else:
            return super(WebSightVerifiedHTTPSConnection, self)._new_conn()

    def connect(self):
        """
        Again, super-hacky. We need to set self.host to the hostname we want to be used for SNI
        connection establishment. For the purpose of ensuring that this doesn't mess other things up,
        we return self.host to the original value once the connection has been returned.
        :return: None
        """
        if self.hostname is not None:
            self.host = self.hostname
            to_return = super(WebSightVerifiedHTTPSConnection, self).connect()
            self.host = self.first_host
            return to_return
        else:
            return super(WebSightVerifiedHTTPSConnection, self).connect()

    @property
    def first_host(self):
        """
        Get the first value that self.host was set to.
        :return: the first value that self.host was set to.
        """
        return self._first_host

    @property
    def host(self):
        """
        Get the host to open a connection to.
        :return: the host to open a connection to.
        """
        return self._host

    @host.setter
    def host(self, new_value):
        """
        Set the value of the host to connect to. If this is the first time the value is set, then
        keep track of the initial set value.
        :param new_value: The value to set.
        :return: None
        """
        self._host = new_value
        if self._first_host is None:
            self._first_host = new_value

    @property
    def hostname(self):
        """
        Get the hostname that this HTTPS connection is meant to use when establishing connections.
        :return: the hostname that this HTTPS connection is meant to use when establishing connections.
        """
        return self._hostname


class WebSightHTTPSConnectionPool(HTTPSConnectionPool):
    """
    This is a custom HTTPS connection pool class that fills out SNI requests based on a set hostname
    instead of the requested URL.
    """

    ConnectionCls = WebSightVerifiedHTTPSConnection

    def __init__(self, *args, **kwargs):
        request_hostname = kwargs.pop("request_hostname", None)
        super(WebSightHTTPSConnectionPool, self).__init__(*args, **kwargs)
        self._hostname = request_hostname
        self.conn_kw["request_hostname"] = self._hostname

    @property
    def hostname(self):
        """
        Get the hostname that should be requested by all HTTPS connections in this pool.
        :return: the hostname that should be requested by all HTTPS connections in this pool.
        """
        return self._hostname


class WebSightPoolManager(PoolManager):
    """
    This is a custom PoolManager class that fills out SNI requests based on a set hostname
    instead of the requested URL.
    """

    def __init__(self, hostname=None, *args, **kwargs):
        self._connection_pool_kw = None
        super(WebSightPoolManager, self).__init__(*args, **kwargs)
        self._hostname = hostname
        self.pool_classes_by_scheme["https"] = WebSightHTTPSConnectionPool
        self.connection_pool_kw["request_hostname"] = hostname

    def _merge_pool_kwargs(self, *args, **kwargs):
        to_return = super(WebSightPoolManager, self)._merge_pool_kwargs(*args, **kwargs)
        if "request_hostname" in to_return:
            to_return.pop("request_hostname")
        return to_return

    @property
    def hostname(self):
        """
        Get the hostname that this poolmanager is configured to establish connections through.
        :return: the hostname that this poolmanager is configured to establish connections through.
        """
        return self._hostname


class WebSightHTTPAdapter(HTTPAdapter):
    """
    This is a custom HTTPAdapter class that fills out SNI requests based on a set hostname
    instead of the requested URL.
    """

    hostname = None
    ssl_version = None

    def init_poolmanager(self, connections, maxsize, block=DEFAULT_POOLBLOCK, **pool_kwargs):
        if self.ssl_version is not None:
            self.poolmanager = WebSightPoolManager(
                hostname=self.hostname,
                num_pools=connections,
                maxsize=maxsize,
                block=block,
                ssl_version=self.ssl_version,
            )
        else:
            self.poolmanager = WebSightPoolManager(
                hostname=self.hostname,
                num_pools=connections,
                maxsize=maxsize,
                block=block,
            )


class WebServiceInspector(BaseInspector):
    """
    This is an inspector class for inspecting web services.
    """

    # Class Members

    # Instantiation

    def __init__(self, ip_address=None, port=None, hostname=None, use_ssl=False, ssl_version=None):
        super(WebServiceInspector, self).__init__()
        self._ip_address = ip_address
        self._port = port
        self._hostname = hostname
        self._use_ssl = use_ssl
        self._ssl_version = ssl_version
        self._url = None
        self._url_wrapper = None
        self._pool_manager_class = None
        self._adapter_class = None
        self._session = None

    # Static Methods

    # Class Methods

    # Public Methods

    def get(self, **kwargs):
        """
        Send an HTTP GET request to the remote endpoint.
        :param kwargs: Keyword arguments to pass to self.send_request.
        :return: A Python requests response object.
        """
        kwargs["verb"] = "GET"
        return self.send_request(**kwargs)

    def send_request(
            self,
            path="/",
            input_hostname=None,
            verb="GET",
            headers={},
            input_ssl_version=None,
            allow_redirects=False,
            wrap_response=True,
            user_agent=config.inspection_user_agent,
            timeout=config.inspection_http_timeout_tuple,
    ):
        """
        Send a request to the remote web service at the given path using the given parameters.
        :param path: The path to request.
        :param input_hostname: The hostname to request.
        :param verb: The HTTP verb to use.
        :param headers: A dictionary of headers to supply alongside the request.
        :param input_ssl_version: The SSL version to use to connect to the remote service.
        :param allow_redirects: Whether or not to follow redirects in the request.
        :param wrap_response: Whether or not to wrap the response in a transactions wrapper, or
        to return the raw requests response.
        :param user_agent: The user agent to supply alongside the request.
        :param timeout: The timeout value to provide to the requests send method.
        :return: A Python requests response object if wrap_response is False, otherwise a
        RequestsTransactionWrapper.
        """
        if allow_redirects:
            raise NotImplementedError(
                "Not implemented! Requests does something super funky with "
                "mounting adapters for following requests, so we should handle "
                "redirections manually."
            )
        url_string = self.url_wrapper.resolve_against(path, as_string=True)
        request_hostname = None
        requires_custom_adapter = False
        if input_hostname is not None and input_hostname != self.hostname:
            request_hostname = input_hostname
            requires_custom_adapter = True
        elif self.hostname is not None:
            request_hostname = self.hostname
        request_ssl_version = None
        if input_ssl_version is not None:
            request_ssl_version = input_ssl_version
            requires_custom_adapter = True
        elif self.ssl_version is not None:
            request_ssl_version = self.ssl_version
        if self.use_ssl:
            if requires_custom_adapter:
                class AnonymousAdapter(WebSightHTTPAdapter):
                    hostname = request_hostname
                    ssl_version = request_ssl_version
                adapter_class = AnonymousAdapter
            else:
                adapter_class = self.adapter_class
            print("Adapter class is: %s (%s)" % (adapter_class, self.adapter_class))
            self.session.mount(self.url, adapter_class())
        if request_hostname is not None:
            headers["Host"] = request_hostname
        headers["User-Agent"] = user_agent
        to_return = self.session.request(
            verb,
            url_string,
            headers=headers,
            allow_redirects=allow_redirects,
            verify=False,
            timeout=timeout,
        )
        if wrap_response:
            return RequestsTransactionWrapper(to_return)
        else:
            return to_return

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def adapter_class(self):
        """
        Get the HTTP adapter class to use to communicate with the remote endpoint.
        :return: the HTTP adapter class to use to communicate with the remote endpoint.
        """
        if self._adapter_class is None:
            class AnonymousAdapter(WebSightHTTPAdapter):
                hostname = self.hostname
                ssl_version = self.ssl_version
            self._adapter_class = AnonymousAdapter
        return self._adapter_class

    @property
    def hostname(self):
        """
        Get the default hostname to request.
        :return: the default hostname to request.
        """
        return self._hostname

    @property
    def inspection_target(self):
        return self.url

    @property
    def ip_address(self):
        """
        Get the IP address where the remote web service resides.
        :return: the IP address where the remote web service resides.
        """
        return self._ip_address

    @property
    def pool_manager_class(self):
        """
        Get the pool manager to use to send requests to the remote endpoint.
        :return: the pool manager to use to send requests to the remote endpoint.
        """
        if self._pool_manager_class is None:
            class ManagerClass(WebSightPoolManager):
                hostname = self.hostname
                ssl_version = self.ssl_version
            self._pool_manager_class = ManagerClass
        return self._pool_manager_class

    @property
    def port(self):
        """
        Get the port where the remote web service resides.
        :return: the port where the remote web service resides.
        """
        return self._port

    @property
    def session(self):
        """
        Get the requests session to use to send requests to the remote endpoint.
        :return: the requests session to use to send requests to the remote endpoint.
        """
        if self._session is None:
            self._session = requests.session()
        return self._session

    @property
    def ssl_version(self):
        """
        Get the SSL version to use to connect to the remote service.
        :return: the SSL version to use to connect to the remote service.
        """
        return self._ssl_version

    @property
    def url(self):
        """
        Get the URL to send requests to.
        :return: the URL to send requests to.
        """
        if self._url is None:
            if self.use_ssl and self.port == 443:
                self._url = "https://%s/" % (self.ip_address,)
            elif not self.use_ssl and self.port == 80:
                self._url = "http://%s/" % (self.ip_address,)
            else:
                self._url = "%s://%s:%s/" % ("https" if self.use_ssl else "http", self.ip_address, self.port)
        return self._url

    @property
    def url_wrapper(self):
        """
        Get a UrlWrapper instance wrapping self.url.
        :return: A UrlWrapper instance wrapping self.url.
        """
        if self._url_wrapper is None:
            self._url_wrapper = UrlWrapper(self.url)
        return self._url_wrapper

    @property
    def use_ssl(self):
        """
        Get whether or not to use SSL to inspect the remote service.
        :return: whether or not to use SSL to inspect the remote service.
        """
        return self._use_ssl

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s:%s (%s, %s)>" % (
            self.__class__.__name__,
            self.ip_address,
            self.port,
            "over SSL" if self.use_ssl else "over plaintext",
            self.hostname,
        )

