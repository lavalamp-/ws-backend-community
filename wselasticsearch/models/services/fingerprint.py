# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseNetworkServiceScanModel
from ..types import *


class ServiceFingerprintModel(BaseNetworkServiceScanModel):
    """
    This is an Elasticsearch model for representing the results of a fingerprinting task.
    """

    # Class Members

    fingerprint_name = KeywordElasticsearchType(
        help_text="A name for the service type that was identified on the referenced network "
                  "service.",
    )
    fingerprint_result = BooleanElasticsearchType(
        help_text="Whether or not the fingerprint succeeded for the network service.",
    )
    ssl_supported = BooleanElasticsearchType(
        help_text="Whether or not the referenced network service supports SSL.",
    )
    ssl_version = KeywordElasticsearchType(
        help_text="The SSL version for the referenced network service fingerprinting process.",
    )

    # Instantiation

    def __init__(
            self,
            fingerprint_name=None,
            fingerprint_result=None,
            ssl_supported=None,
            ssl_version=None,
            **kwargs
    ):
        super(ServiceFingerprintModel, self).__init__(**kwargs)
        self.ssl_supported = ssl_supported
        self.ssl_version = ssl_version
        self.fingerprint_result = fingerprint_result
        self.fingerprint_name = fingerprint_name

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.ssl_supported = RandomHelper.flip_coin()
        to_populate.ssl_version = WsFaker.get_ssl_version_name()
        to_populate.fingerprint_result = RandomHelper.flip_coin()
        to_populate.fingerprint_name = WsFaker.get_fingerprint_service_name()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class VirtualHostFingerprintModel(BaseNetworkServiceScanModel):
    """
    This is an Elasticsearch model class for maintaining data about fingerprints retrieved from
    web servers for the purpose of virtual host discovery.
    """

    # Class Members

    response_code = IntElasticsearchType(
        help_text="The HTTP status code for the HTTP fingerprinting response."
    )
    response_has_content = BooleanElasticsearchType(
        help_text="Whether or not content was returned in HTTP fingerprinting response.",
    )
    response_mime_type = KeywordElasticsearchType(
        help_text="The MIME type that was returned in the HTTP fingerprinting response.",
    )
    response_primary_hash = KeywordElasticsearchType(
        help_text="A cryptographic hash of the contents that were returned by the HTTP "
                  "fingerprinting response.",
    )
    response_secondary_hash = KeywordElasticsearchType(
        help_text="A secondary hash representing the content returned by the HTTP "
                  "fingerprinting response (contents of secondary hash depend on MIME type).",
    )
    over_ssl = BooleanElasticsearchType(
        help_text="Whether or not the HTTP fingerprinting request was submitted over SSL.",
    )
    hostname = KeywordElasticsearchType(
        help_text="The virtual host name that was submitted in the fingerprinting request.",
    )

    # Instantiation

    def __init__(
            self,
            response_code=None,
            response_has_content=None,
            response_mime_type=None,
            response_primary_hash=None,
            response_secondary_hash=None,
            over_ssl=None,
            hostname=None,
            **kwargs
    ):
        super(VirtualHostFingerprintModel, self).__init__(**kwargs)
        self.response_code = response_code
        self.response_has_content = response_has_content
        self.response_mime_type = response_mime_type
        self.response_primary_hash = response_primary_hash
        self.response_secondary_hash = response_secondary_hash
        self.over_ssl = over_ssl
        self.hostname = hostname

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.response_code = WsFaker.get_http_response_status()
        to_populate.response_has_content = RandomHelper.flip_coin()
        to_populate.response_mime_type = WsFaker.get_mime_string()
        to_populate.response_primary_hash = WsFaker.get_sha256_string()
        to_populate.response_secondary_hash = WsFaker.get_sha256_string()
        to_populate.over_ssl = RandomHelper.flip_coin()
        to_populate.hostname = WsFaker.get_domain_name()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
