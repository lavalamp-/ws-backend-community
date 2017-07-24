# -*- coding: utf-8 -*-
from __future__ import absolute_import

import boto3
from uuid import uuid4

from .singleton import Singleton
from .config import ConfigManager

config = ConfigManager.instance()


@Singleton
class S3Helper(object):
    """
    This class contains helper methods for interacting with AWS S3.
    """

    # Class Members

    # Instantiation

    def __init__(self):
        self._s3 = None

    # Static Methods

    # Class Methods

    # Public Methods

    def create_bucket(self, name=None, acl=config.aws_s3_default_acl):
        """
        Create a bucket with the given name.
        :param name: The name to give the bucket.
        :param acl: The ACL to apply to the bucket.
        :return: The AWS boto3 client response.
        """
        return self.s3.create_bucket(
            Bucket=name,
            ACL=acl,
            CreateBucketConfiguration=self.create_bucket_constraint,
        )

    def create_default_bucket(self):
        """
        Create the default bucket used by this version of Web Sight.
        :return: The boto3 client response.
        """
        return self.create_bucket(
            name=config.storage_bucket,
            acl=config.aws_s3_default_acl,
        )

    def get_buckets(self):
        """
        Get a list of currently available S3 buckets.
        :return: A list of currently available S3 buckets.
        """
        return self.s3.list_buckets()

    def get_file(self, file_key=None, bucket=config.storage_bucket):
        """
        Get the contents of the file specified by file_key from the given bucket.
        :param file_key: The key where the file resides.
        :param bucket: The bucket where the file resides.
        :return: The contents of the file referenced by file_key and bucket.
        """
        response = self.s3.get_object(Bucket=bucket, Key=file_key)
        return response["Body"].read()

    def get_key(self, org_uuid=None, path_component=None):
        """
        Get an S3 key to use for uploading a file.
        :param org_uuid: The UUID of the organizations to associate with the file.
        :param path_component: The path component to add to the key.
        :return: An S3 key to use for uploading a file.
        """
        path_segments = [org_uuid] if org_uuid is not None else []
        path_segments.extend([path_component, str(uuid4())])
        return "/".join(path_segments)

    def get_key_for_bad_html(self):
        """
        Get an S3 key to use for uploading a HTML that Web Sight errored when parsing.
        :return: An S3 key to use for uploading a HTML that Web Sight errored when parsing.
        """
        return self.get_key(path_component=config.storage_bad_html_path)

    def get_key_for_dns_text_file(self, org_uuid):
        """
        Get a key to use for uploading a DNS text file for the given user.
        :param org_uuid: The UUID of the organization that uploaded the DNS text file.
        :return: A string containing a key to use for uploading a DNS text file for the
        given user.
        """
        return self.get_key(org_uuid=org_uuid, path_component=config.storage_uploads_path)

    def get_key_for_screenshot(self, org_uuid):
        """
        Get a key to use for uploading a screenshot for the given organization.
        :param org_uuid: The UUID of the organization that owns the screenshot.
        :return: A string containing a key to use for uploading a screenshot for the
        given organization.
        """
        return self.get_key(org_uuid=org_uuid, path_component=config.storage_screenshots_path)

    def get_key_for_ssl_certificate(self, org_uuid):
        """
        Get a key to use for uploading an SSL certificate for the given organization.
        :param org_uuid: The UUID of the organization that owns the SSL certificate.
        :return: A string containing a key to use for uploading an SSL certificate for the
        given organization.
        """
        return self.get_key(org_uuid=org_uuid, path_component=config.storage_certificates_path)

    def get_signed_url_for_key(self, key=None, bucket=config.storage_bucket):
        """
        Generate and return a signed URL for the given key and bucket.
        :param key: The key to generate the URL for.
        :param bucket: The bucket where the key resides.
        :return: A signed URL that can be used to access the object stored at the given
        key in the given bucket.
        """
        return self.s3.generate_presigned_url(
            ClientMethod="get_object",
            Params={
                "Bucket": bucket,
                "Key": key,
            }
        )

    def upload_file_to_bucket(
            self,
            bucket=config.storage_bucket,
            local_file_path=None,
            file_obj=None,
            key=None,
            acl=config.aws_s3_default_acl,
    ):
        """
        Upload the file at the given path to the given bucket with the given key.
        :param bucket: The name of the bucket to upload the file to.
        :param local_file_path: The local path where the file resides.
        :param file_obj: The file object to upload. Note that only this value or local_file_path should
        be populated.
        :param key: The key to upload the file under.
        :param acl: The ACL to apply to the newly-uploaded item.
        :return: The boto3 response.
        """
        if file_obj is None:
            file_obj = open(local_file_path, "rb")
        return self.s3.put_object(
            ACL=acl,
            Body=file_obj,
            Bucket=bucket,
            Key=key,
        )

    def upload_bad_html(self, local_file_path=None, bucket=config.storage_bucket):
        """
        Upload the given malformed HTML file to S3.
        :param local_file_path: The local file path where the malformed HTML resides.
        :param bucket: The name of the bucket to upload the file to.
        :return: A tuple containing (1) the boto3 response, and (2) the key that the HTML is
        stored in S3 under.
        """
        file_key = self.get_key_for_bad_html()
        response = self.upload_file_to_bucket(
            local_file_path=local_file_path,
            key=file_key,
            bucket=bucket,
        )
        return response, file_key

    def upload_dns_text_file(
            self,
            org_uuid=None,
            local_file_path=None,
            bucket=config.storage_bucket,
            file_obj=None,
    ):
        """
        Upload the given DNS text file to S3.
        :param org_uuid: The UUID of the user that uploaded the file.
        :param local_file_path: The local file path where the DNS text file resides.
        :param bucket: The name of the bucket to upload the file to.
        :param file_obj: A file object to upload. Note that only this value or local_file_path should
        be populated.
        :return: A tuple containing (1) the boto3 response, and (2) the key that the DNS file
        is stored under.
        """
        file_key = self.get_key_for_dns_text_file(org_uuid)
        response = self.upload_file_to_bucket(
            local_file_path=local_file_path,
            key=file_key,
            bucket=bucket,
            file_obj=file_obj,
        )
        return response, file_key

    def upload_screenshot(self, org_uuid=None, local_file_path=None, bucket=config.storage_bucket):
        """
        Upload the given screenshot to S3 on behalf of the given organization.
        :param org_uuid: The UUID of the organization that owns the screenshot.
        :param local_file_path: The local file path where the screenshot resides.
        :param bucket: The name of the bucket to upload the file to.
        :return: A tuple containing (1) the boto3 response, and (2) the key that the image
        is stored in S3 under.
        """
        file_key = self.get_key_for_screenshot(org_uuid)
        response = self.upload_file_to_bucket(
            local_file_path=local_file_path,
            key=file_key,
            bucket=bucket,
        )
        return response, file_key

    def upload_ssl_certificate(self, org_uuid=None, local_file_path=None, bucket=config.storage_bucket):
        """
        Upload the given SSL certificate to S3 on behalf of the given organization.
        :param org_uuid: The UUID of the organization that owns the SSL certificate.
        :param local_file_path: The local file path where the SSL certificate resides.
        :param bucket: The name of the bucket to upload the file to.
        :return: A tuple containing (1) the boto3 response, and (2) the key that the certificate is stored
        in S3 under.
        """
        file_key = self.get_key_for_ssl_certificate(org_uuid=org_uuid)
        response = self.upload_file_to_bucket(
            local_file_path=local_file_path,
            key=file_key,
            bucket=bucket,
        )
        return response, file_key

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def create_bucket_constraint(self):
        """
        Get an AWS S3 constraint for use when creating new buckets.
        :return: An AWS S3 constraint for use when creating new buckets.
        """
        return {
            "LocationConstraint": config.aws_default_region,
        }

    @property
    def s3(self):
        """
        Get the boto3 s3 connection to use to communicate with AWS S3.
        :return: the boto3 s3 connection to use to communicate with AWS S3.
        """
        if self._s3 is None:
            self._s3 = boto3.client(
                "s3",
                aws_access_key_id=config.aws_key_id,
                aws_secret_access_key=config.aws_secret_key,
            )
        return self._s3

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)

