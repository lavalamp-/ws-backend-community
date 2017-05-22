# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .types import *


class DomainNameMixin(object):
    """
    This is a mixin class that is used to add a domain_names property to models.
    """

    domain_names = KeywordElasticsearchType()


class ServiceMixin(object):
    """
    This is a mixin class that is used to add a service_uuid property to models.
    """

    service_uuid = KeywordElasticsearchType()


class IpAddressMixin(object):
    """
    This is a mixin class that is used to add an ip_address property to models.
    """

    ip_address = KeywordElasticsearchType()


class ServiceEndpointMixin(ServiceMixin, IpAddressMixin):
    """
    This is a mixin class that is used to add a service_uuid as well as an IP address, port, and protocol
    to a model.
    """

    port = IntElasticsearchType()
    protocol = TextElasticsearchType()


class S3Mixin(object):
    """
    This is a mixin class that is used to add a bucket and key corresponding to a file that has been
    uploaded to S3.
    """

    s3_bucket = KeywordElasticsearchType()
    s3_key = KeywordElasticsearchType()
    s3_file_type = KeywordElasticsearchType()

    def set_s3_attributes(self, bucket=None, key=None, file_type=None):
        """
        Set the AWS S3 attributes for this model.
        :param bucket: The bucket the file is stored in.
        :param key: The key the file is stored under.
        :param file_type: The file type that this model represents.
        :return: None
        """
        self.s3_bucket = bucket
        self.s3_key = key
        self.s3_file_type = file_type


class SslSupportRelatedMixin(object):
    """
    This is a mixin class that is used to associate an Elasticsearch model with data contained within
    an SSL support report.
    """

    ssl_certificate_cname = KeywordElasticsearchType()
    ssl_certificate_expired = BooleanElasticsearchType()
    ssl_certificate_is_valid = BooleanElasticsearchType()
    ssl_certificate_start_time = DateElasticsearchType()
    ssl_certificate_invalid_time = DateElasticsearchType()
    ssl_certificate_md5_digest = KeywordElasticsearchType()
    has_ssl_certificate_data = BooleanElasticsearchType()

    def populate_from_ssl_support(self, ssl_support=None):
        """
        Populate the contents of this mixin class based on the contents of the given SSL support report.
        :param ssl_support: An SSL support report to process.
        :return: None
        """
        if ssl_support is None:
            self.has_ssl_certificate_data = False
            self.ssl_certificate_cname = None
            self.ssl_certificate_expired = None
            self.ssl_certificate_is_valid = None
            self.ssl_certificate_start_time = None
            self.ssl_certificate_invalid_time = None
            self.ssl_certificate_md5_digest = None
        else:
            self.has_ssl_certificate_data = True
            self.ssl_certificate_cname = ssl_support.cert_subject_common_name
            self.ssl_certificate_expired = ssl_support.cert_expired
            self.ssl_certificate_is_valid = ssl_support.cert_is_valid
            self.ssl_certificate_start_time = ssl_support.cert_start_time
            self.ssl_certificate_invalid_time = ssl_support.cert_invalid_time
            self.ssl_certificate_md5_digest = ssl_support.cert_md5_digest
