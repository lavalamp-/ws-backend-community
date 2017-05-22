# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWrapper
import OpenSSL
from lib import BaseWsException, RegexLib


class CertificateExtensionNotFoundError(BaseWsException):
    """
    This is an exception for denoting that the inspector was passed an extension name that was not
    contained within the referenced SSL certificate.
    """

    _message = "Extension not found."


class SslCertificateWrapper(BaseWrapper):
    """
    This is a wrapper class for wrapping an SSL certificate.
    """

    # Class Members

    # Instantiation

    def __init__(self, to_wrap, cert_type=OpenSSL.crypto.FILETYPE_PEM):
        self._cert_type = cert_type
        self._certificate = None
        self._extension_names = None
        self._authority_info_access = None
        self._parent_cert_urls = None
        super(SslCertificateWrapper, self).__init__(to_wrap)

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _process_data(self):
        self._certificate = OpenSSL.crypto.load_certificate(self.cert_type, self.wrapped_data)

    # Private Methods

    def __get_extension_content(self, extension_name):
        """
        Get a string representing the content of the given extension.
        :param extension_name: The name of the extension to retrieve content for.
        :return: A string representing the content of the given extension.
        """
        for i in range(self.certificate.get_extension_count()):
            extension = self.certificate.get_extension(i)
            if extension.get_short_name() == extension_name:
                return str(extension)
        raise CertificateExtensionNotFoundError(
            "Extension with name %s was not found in SSL certificate."
            % (extension_name,)
        )

    # Properties

    @property
    def authority_info_access(self):
        """
        Get the authority info access from the certificate extensions of the extensions contain it.
        :return: the authority info access from the certificate extensions of the extensions contain it.
        """
        if self._authority_info_access is None and self.has_authority_info_access:
            self._authority_info_access = self.__get_extension_content("authorityInfoAccess")
        return self._authority_info_access

    @property
    def cert_type(self):
        """
        Get the OpenSSL certificate format that self.wrapped_data is in.
        :return: the OpenSSL certificate format that self.wrapped_data is in.
        """
        return self._cert_type

    @property
    def certificate(self):
        """
        Get an OpenSSL X509 certificate representing the contents of self.wrapped_data.
        :return: an OpenSSL X509 certificate representing the contents of self.wrapped_data.
        """
        return self._certificate

    @property
    def extension_names(self):
        """
        Get a list of names representing the extensions found within the SSL certificate.
        :return: a list of names representing the extensions found within the SSL certificate.
        """
        if self._extension_names is None:
            names = []
            for i in range(self.certificate.get_extension_count()):
                names.append(self.certificate.get_extension(i).get_short_name())
            self._extension_names = names
        return self._extension_names

    @property
    def has_authority_info_access(self):
        """
        Get whether or not the certificate has the authorityInfoAccess extension.
        :return: whether or not the certificate has the authorityInfoAccess extension.
        """
        return "authorityInfoAccess" in self.extension_names

    @property
    def has_parent_cert_url(self):
        """
        Get whether or not this certificate has a reference to its parent certificate URL.
        :return: whether or not this certificate has a reference to its parent certificate URL.
        """
        return len(self.parent_cert_urls) > 0

    @property
    def parent_cert_urls(self):
        """
        Get a list of the URLs where the parent certificate for this certificate resides.
        :return: a list of the URLs where the parent certificate for this certificate resides.
        """
        if self._parent_cert_urls is None and self.has_authority_info_access:
            issuers_lines = filter(lambda x: "ca issuers" in x.lower(), self.authority_info_access.split("\n"))
            if len(issuers_lines) == 0:
                self._parent_cert_urls = []
            else:
                parent_urls = []
                for line in issuers_lines:
                    url = RegexLib.authority_info_uri_regex.findall(line)[0].strip()
                    parent_urls.append(url)
                self._parent_cert_urls = parent_urls
        return self._parent_cert_urls

    @property
    def preferred_parent_cert_url(self):
        """
        Get the URL for the certificate parent within the wrapped certificate that is preferred for use by
        Web Sight SSL inspection.
        :return: the URL for the certificate parent within the wrapped certificate that is preferred for
        use by Web Sight SSL inspection.
        """
        if len(self.parent_cert_urls) > 0:
            results = filter(lambda x: x.lower().endswith("crt"), self.parent_cert_urls)
            if len(results) > 0:
                return results[0]
            else:
                return self.parent_cert_urls[0]
        else:
            return None

    @property
    def wrapped_type(self):
        return "SSL Certificate"

    # Representation and Comparison
