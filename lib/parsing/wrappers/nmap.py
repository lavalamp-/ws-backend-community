# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lxml import etree

from lib import ValidationHelper, FilesystemHelper
from .base import BaseWrapper


class BaseNmapWrapper(BaseWrapper):
    """
    This is a mixin class that provides some default functionality for parsing XML found in Nmap XML files.
    """

    def __init__(self, *args, **kwargs):
        self._base_element = None
        super(BaseNmapWrapper, self).__init__(*args, **kwargs)

    def _process_data(self):
        self._base_element = etree.fromstring(self.wrapped_data)

    def _retrieve_attribute(self, attribute, xpath_string):
        """
        Attempt to retrieve the given attribute from the current class. If the attribute
        is not found, this method attempts to fill the attribute using the xpath_string on the
        element tree at self._etree.
        :param attribute: The class attribute to attempt retrieval for.
        :param xpath_string: The xpath string to fill the attribute from the element tree with.
        :return: The class attribute corresponding to the attribute argument.
        """
        to_return = getattr(self, attribute)
        if to_return is None:
            element = self._base_element.xpath(xpath_string)
            if element:
                setattr(self, attribute, element[0])
            else:
                setattr(self, attribute, "")
        return getattr(self, attribute)


class NmapPortWrapper(BaseNmapWrapper):
    """
    This class is a wrapper class to be placed around Nmap port objects.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        self._protocol = None
        self._port_number = None
        self._state = None
        self._state_reason = None
        self._service_name = None
        self._service_product = None
        self._extra_service_info = None
        self._script_ids = None
        self._cpe_text = None
        self._service_fingerprint = None
        super(NmapPortWrapper, self).__init__(*args, **kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def cpe_text(self):
        """
        Get the contents of the <cpe> tag if it exists.
        :return: The contents of the <cpe> tag if it exists.
        """
        if self._cpe_text is None:
            if self._base_element.xpath(".//cpe"):
                self._cpe_text = self._base_element.xpath(".//cpe")[0].text
            else:
                self._cpe_text = ""
        return self._cpe_text

    @property
    def extra_service_info(self):
        """
        Get any extra information supplied about the port's service.
        :return: Any extra information supplied about the port's service.
        """
        return self._retrieve_attribute("_extra_service_info", ".//service/@extrainfo")

    @property
    def is_web_service(self):
        """
        Get whether or not the service on this port represents a web service.
        :return: True if the service on this port represents a web service, False otherwise.
        """
        if "http" in self.service_product:
            return True
        elif "http" in self.service_name:
            return True
        elif any(["http" in x for x in self.script_ids]):
            return True
        elif "http_server" in self.cpe_text:
            return True
        elif "HTTP/1" in self.service_fingerprint:
            return True
        else:
            return False

    @property
    def port_number(self):
        """
        Get the number of the port.
        :return: The number of the port.
        """
        return self._retrieve_attribute("_port_number", "@portid")

    @property
    def protocol(self):
        """
        Get the protocol of the port.
        :return: The protocol of the port.
        """
        return self._retrieve_attribute("_protocol", "@protocol")

    @property
    def service_fingerprint(self):
        """
        Get the port's service fingerprint.
        :return: The port's service fingerprint.
        """
        return self._retrieve_attribute("_service_fingerprint", ".//service/@servicefp")

    @property
    def script_ids(self):
        """
        Get the IDs of any <script> tags contained within this port.
        :return: The IDs of any <script> tags contained within this port.
        """
        return self._retrieve_attribute("_script_ids", ".//script/@id")

    @property
    def service_name(self):
        """
        Get the service name for the port.
        :return: The service name for the port.
        """
        return self._retrieve_attribute("_service_name", ".//service/@name")

    @property
    def service_product(self):
        """
        Get the service product for the port.
        :return: The service product for the port.
        """
        return self._retrieve_attribute("_service_product", ".//service/@product")

    @property
    def state(self):
        """
        Get the state of the port.
        :return: The state of the port.
        """
        return self._retrieve_attribute("_state", ".//state/@state")

    @property
    def state_reason(self):
        """
        Get how the given state was determined.
        :return: How the given state was determined.
        """
        return self._retrieve_attribute("_state_reason", ".//state/@reason")

    @property
    def wrapped_type(self):
        return "Nmap XML File Port"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s %s (%s)>" % (
            self.__class__.__name__,
            self.port_number,
            self.protocol,
            self.state,
        )


class NmapHostnameWrapper(BaseNmapWrapper):
    """
    This class is a wrapper class to be placed around Nmap hostname elements.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        self._name = None
        self._type = None
        super(NmapHostnameWrapper, self).__init__(*args, **kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def name(self):
        """
        Get the name of the hostname.
        :return: The name of the hostname.
        """
        return self._retrieve_attribute("_name", ".//@name")

    @property
    def type(self):
        """
        Get the type of the hostname.
        :return: The type of the hostname.
        """
        return self._retrieve_attribute("_type", ".//@type")

    @property
    def wrapped_type(self):
        return "Nmap XML File Hostname"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (
            self.__class__.__name__,
            self.name,
        )


class NmapHostWrapper(BaseNmapWrapper):
    """
    This class is a wrapper class to be placed around Nmap host objects.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        self._start_time = None
        self._end_time = None
        self._ip_address = None
        self._address_type = None
        self._status = None
        self._hostnames = None
        self._ports = None
        self._os = None
        self._uptime = None
        super(NmapHostWrapper, self).__init__(*args, **kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def address_type(self):
        """
        Get the host's IP address type.
        :return: The host's IP address type.
        """
        return self._retrieve_attribute("_address_type", ".//address/@addrtype")

    @property
    def end_time(self):
        """
        Get when the host stopped being scanned.
        :return: When the host stopped being scanned.
        """
        return self._retrieve_attribute("_end_time", "@endtime")

    @property
    def hostnames(self):
        """
        Get the Nmap hosts contained within the Nmap XML file.
        :return: The Nmap hosts contained within the Nmap XML file.
        """
        if self._hostnames is None:
            self._hostnames = [NmapHostnameWrapper(etree.tostring(x)) for x in self._base_element.xpath(".//hostname")]
        return self._hostnames

    @property
    def ip_address(self):
        """
        Get the host's IP address.
        :return: The host's IP address.
        """
        return self._retrieve_attribute("_ip_address", ".//address/@addr")

    @property
    def open_ports(self):
        """
        Get a list of the ports found within this host that are marked as open.
        :return: a list of the ports found within this host that are marked as open.
        """
        return filter(lambda x: "open" in x.state, self.ports)

    @property
    def open_ports_count(self):
        """
        Get the number of open ports found on this host.
        :return: the number of open ports found on this host.
        """
        return len(self.open_ports)

    @property
    def os(self):
        """
        Get the host's operating system.
        :return: The host's operating system.
        """
        return self._retrieve_attribute("_os", ".//osmatch/@name")

    @property
    def ports(self):
        """
        Get the Nmap ports contained within the Nmap XML file.
        :return: The Nmap ports contained within the Nmap XML file.
        """
        if self._ports is None:
            self._ports = [NmapPortWrapper(etree.tostring(x)) for x in self._base_element.xpath(".//port")]
        return self._ports

    @property
    def start_time(self):
        """
        Get when the host started being scanned.
        :return: When the host started being scanned.
        """
        return self._retrieve_attribute("_start_time", "@starttime")

    @property
    def status(self):
        """
        Get the host's "UP" state.
        :return: The host's "UP" state.
        """
        return self._retrieve_attribute("_status", ".//status/@state")

    @property
    def uptime(self):
        """
        Get the host's up time.
        :return: The host's up time.
        """
        return self._retrieve_attribute("_uptime", ".//uptime/@seconds")

    @property
    def wrapped_type(self):
        return "Nmap XML File Host"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s open ports)>" % (
            self.__class__.__name__,
            self.ip_address,
            self.open_ports_count,
        )


class NmapXmlWrapper(BaseNmapWrapper):
    """
    This class is a wrapper class to be placed around Nmap XML files. It allows for easy access to
    Nmap XML file objects and attributes.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        self._file_path = None
        self._command_line = None
        self._scan_type = None
        self._start_time = None
        self._scan_protocol = None
        self._num_services = None
        self._services_info = None
        self._hosts = None
        self._up_hosts = None
        self._down_hosts = None
        self._total_hosts = None
        self._end_time = None
        super(NmapXmlWrapper, self).__init__(*args, **kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    def get_results_for_ip_address(self, ip_address):
        """
        Get the scan results for the given IP address if the given IP address is found in
        this results file.
        :param ip_address: The IP address to get results for.
        :return: The scan results for the given IP address if the given IP address is found in this
        results file, otherwise None.
        """
        matches = filter(lambda x: x.ip_address == ip_address, self.hosts)
        if len(matches) > 0:
            return matches[0]
        else:
            return None

    # Protected Methods

    def _process_data(self):
        self._base_element = etree.fromstring(self.wrapped_data)

    # Private Methods

    # Properties

    @property
    def command_line(self):
        """
        Get the command that was issued to start the Nmap scan.
        :return: The command that was issued to start the Nmap scan.
        """
        return self._retrieve_attribute("_command_line", "//nmaprun/@args")

    @property
    def end_time(self):
        """
        Get the time that the Nmap scan concluded.
        :return: The time that the Nmap scan concluded.
        """
        return self._retrieve_attribute("_end_time", "//finished/@time")

    @property
    def down_hosts(self):
        """
        Get the number of down hosts in the scan.
        :return: The number of down hosts in the scan.
        """
        return self._retrieve_attribute("_down_hosts", "//hosts/@down")

    @property
    def hosts(self):
        """
        Get the Nmap hosts contained within the Nmap XML file.
        :return: The Nmap hosts contained within the Nmap XML file.
        """
        if self._hosts is None:
            self._hosts = [NmapHostWrapper(etree.tostring(x)) for x in self._base_element.xpath("//host")]
        return self._hosts

    @property
    def num_services(self):
        """
        Get the number of services scanned.
        :return: The number of services scanned.
        """
        return self._retrieve_attribute("_num_services", "//scaninfo/@numservices")

    @property
    def scan_protocol(self):
        """
        Get the protocol use for the Nmap scan.
        :return: The protocol used for the Nmap scan.
        """
        return self._retrieve_attribute("_scan_protocol", "//scaninfo/@protocol")

    @property
    def scan_type(self):
        """
        Get the type of the Nmap scan.
        :return: The type of the Nmap scan.
        """
        return self._retrieve_attribute("_scan_type", "//scaninfo/@type")

    @property
    def services_info(self):
        """
        Get the specific scanned services.
        :return: The specific scanned services.
        """
        return self._retrieve_attribute("_services_info", "//scaninfo/@services")

    @property
    def start_time(self):
        """
        Get the time at which the Nmap scan started.
        :return: The time at which the Nmap scan started.
        """
        return self._retrieve_attribute("_start_time", "//nmaprun/@start")

    @property
    def total_hosts(self):
        """
        Get the total number of hosts in the scan.
        :return: The total number of hosts in the scan.
        """
        return self._retrieve_attribute("_total_hosts", "//hosts/@total")

    @property
    def up_hosts(self):
        """
        Get the number of live hosts in the scan.
        :return: The number of live hosts in the scan.
        """
        return self._retrieve_attribute("_up_hosts", "//hosts/@up")

    @property
    def wrapped_type(self):
        return "Nmap XML File"

    # Representation and Comparison
