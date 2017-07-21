# -*- coding: utf-8 -*-
from __future__ import absolute_import

from uuid import uuid4
from google.cloud import storage

from .singleton import Singleton
from .config import ConfigManager

config = ConfigManager.instance()


class RemoteStorageHelper(object):
    """
    This is a base class for helper classes that provide functionality for storing
    data in various cloud storage provider.
    """

    # Class Members

    DEFAULT_ACL = None
    DEFAULT_BUCKET = None

    # Instantiation

    def __init__(self):
        self._client = None

    # Static Methods

    # Class Methods

    # Public Methods

    def create_bucket(self, name=None, acl=DEFAULT_ACL):
        """
        Create a new bucket using the given name.
        :param name: The name of the bucket to create.
        :param acl: The ACL to apply to the bucket.
        :return:
        """
        raise NotImplementedError("Subclasses must implement this!")

    def create_default_bucket(self):
        """
        Create the default bucket used by this version of Web Sight.
        :return:
        """
        return self.create_bucket(
            name=self.DEFAULT_BUCKET,
            acl=self.DEFAULT_ACL,
        )

    def get_buckets(self):
        """
        Get a list of currently available buckets.
        :return: A list of currently available buckets.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def get_file(self, file_key=None, bucket=config.aws_s3_bucket):
        """
        Get the specified field from the specified bucket.
        :param file_key: A string depicting the key of the file to retrieve.
        :param bucket: The bucket to retrieve the file from.
        :return: The contents of the file referenced by file_key and bucket.
        """
        raise NotImplementedError("Subclasses must implement this!")

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
        return self.get_key(path_component=config.aws_s3_bad_html_path)

    def get_key_for_dns_text_file(self, org_uuid):
        """
        Get a key to use for uploading a DNS text file for the given user.
        :param org_uuid: The UUID of the organization that uploaded the DNS text file.
        :return: A string containing a key to use for uploading a DNS text file for the
        given user.
        """
        return self.get_key(org_uuid=org_uuid, path_component=config.aws_s3_uploads_path)

    def get_key_for_screenshot(self, org_uuid):
        """
        Get a key to use for uploading a screenshot for the given organization.
        :param org_uuid: The UUID of the organization that owns the screenshot.
        :return: A string containing a key to use for uploading a screenshot for the
        given organization.
        """
        return self.get_key(org_uuid=org_uuid, path_component=config.aws_s3_screenshots_path)

    def get_key_for_ssl_certificate(self, org_uuid):
        """
        Get a key to use for uploading an SSL certificate for the given organization.
        :param org_uuid: The UUID of the organization that owns the SSL certificate.
        :return: A string containing a key to use for uploading an SSL certificate for the
        given organization.
        """
        return self.get_key(org_uuid=org_uuid, path_component=config.aws_s3_certificates_path)

    def get_signed_url_for_key(self, key=None, bucket=config.aws_s3_bucket):
        """
        Generate and return a signed URL for the given key and bucket.
        :param key: The key to generate the URL for.
        :param bucket: The bucket where the key resides.
        :return: A signed URL that can be used to access the object stored at the given
        key in the given bucket.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def upload_file_to_bucket(
            self,
            bucket=config.aws_s3_bucket,
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
        :return:
        """
        raise NotImplementedError("Subclasses must implement this!")

    def upload_bad_html(self, local_file_path=None, bucket=config.aws_s3_bucket):
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
            bucket=config.aws_s3_bucket,
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

    def upload_screenshot(self, org_uuid=None, local_file_path=None, bucket=config.aws_s3_bucket):
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

    def upload_ssl_certificate(self, org_uuid=None, local_file_path=None, bucket=config.aws_s3_bucket):
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

    def _get_client(self):
        """
        Get a client to use to communicate with the storage service.
        :return: A client to use to communicate with the storage service.
        """
        raise NotImplementedError("Subclasses must implement this!")

    # Private Methods

    # Properties

    @property
    def client(self):
        """
        Get a client to use to communicate with the storage service.
        :return: a client to use to communicate with the storage service.
        """
        if self._client is None:
            self._client = self._get_client()
        return self._client

    # Representation and Comparison


@Singleton
class GcsStorageHelper(RemoteStorageHelper):
    """
    This is a class for interacting with Google Cloud Storage.
    """

    DEFAULT_ACL = None
    DEFAULT_BUCKET = None

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def create_bucket(self, name=None, acl=DEFAULT_ACL):
        bucket = self.client.create_bucket(name)
        bucket.acl.save(acl=acl)
        return bucket

    def get_buckets(self):
        return list(self.client.list_buckets())

    def get_file(self, file_key=None, bucket=DEFAULT_BUCKET):
        blob = self.__get_blob(file_key=file_key, bucket=bucket)
        return blob.download_as_string()

    def get_signed_url_for_key(self, key=None, bucket=DEFAULT_BUCKET):
        blob = self.__get_blob(file_key=key, bucket=bucket)
        return blob.generate_signed_url(60*60*24)

    def upload_file_to_bucket(
            self,
            bucket=DEFAULT_BUCKET,
            local_file_path=None,
            file_obj=None,
            key=None,
            acl=DEFAULT_ACL,
    ):
        blob = self.__create_blob(file_key=key, bucket=bucket)
        if local_file_path:
            to_return = blob.upload_from_filename(local_file_path)
        elif file_obj:
            to_return = blob.upload_from_file(file_obj)
        else:
            raise ValueError("No file object or file path passed to upload_file_to_bucket.")
        to_return.acl.save(acl=acl)
        return to_return

    # Protected Methods

    def _get_client(self):
        return storage.Client()

    # Private Methods

    def __create_blob(self, file_key=None, bucket=None):
        """
        Create a new blob in the specified bucket using the specified file key.
        :param file_key: The key that the file should be stored under.
        :param bucket: The bucket where the file should be stored.
        :return: The newly-created blob.
        """
        bucket = self.client.get_bucket(bucket)
        return bucket.blob(file_key)

    def __get_blob(self, file_key=None, bucket=None):
        """
        Get a GCS blob from the specified bucket stored at the specified file key.
        :param file_key: The key to the file to retrieve.
        :param bucket: The bucket to retrieve the file from.
        :return: A GCS blob for the referenced file.
        """
        bucket = self.client.get_bucket(bucket)
        return bucket.get_blob(file_key)

    # Properties

    # Representation and Comparison
