# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseUserModel
from ..types import *
from lib import DatetimeHelper
from ..mixin import S3Mixin


class UserOrganizationSelectModel(BaseUserModel):
    """
    This is an Elasticsearch model for keeping track of the organizations that a user has selected.
    """

    # Class Members

    org_uuid = KeywordElasticsearchType()
    org_name = KeywordElasticsearchType()
    selected_at = DateElasticsearchType()

    # Instantiation

    def __init__(self, org_uuid=None, org_name=None, *args, **kwargs):
        super(UserOrganizationSelectModel, self).__init__(*args, **kwargs)
        self.org_uuid = org_uuid
        self.org_name = org_name
        self.selected_at = DatetimeHelper.now()

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.org_uuid = WsFaker.create_uuid()
        to_populate.org_name = WsFaker.get_words(1)[0]
        to_populate.selected_at = WsFaker.get_time_in_past()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class UserUploadModel(BaseUserModel, S3Mixin):
    """
    This is an Elasticsearch model for keeping track of files that are uploaded by a user.
    """

    # Class Members

    upload_type = KeywordElasticsearchType()

    # Instantiation

    def __init__(self, upload_type=None, bucket=None, key=None, *args, **kwargs):
        super(UserUploadModel, self).__init__(*args, **kwargs)
        self.upload_type = upload_type
        self.s3_bucket = bucket
        self.s3_key = key
        self.s3_file_type = upload_type

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker
        to_populate.upload_type = WsFaker.get_words(1)[0]
        to_populate.set_s3_attributes(**WsFaker.get_s3_mixin_dictionary())
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
