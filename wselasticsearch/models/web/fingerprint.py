# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWebServiceScanModel
from ..types import *


class UserAgentFingerprintModel(BaseWebServiceScanModel):
    """
    This is an Elasticsearch model class for maintaining data about user agent fingerprints retrieved
    from web servers.
    """

    # Class Members

    user_agent_type = KeywordElasticsearchType()
    user_agent_name = KeywordElasticsearchType()
    user_agent_string = KeywordElasticsearchType()
    response_has_content = BooleanElasticsearchType()
    response_mime_type = KeywordElasticsearchType()
    response_primary_hash = KeywordElasticsearchType()
    response_secondary_hash = KeywordElasticsearchType()
    response_status_code = IntElasticsearchType()

    # Instantiation

    def __init__(
            self,
            user_agent_type=None,
            user_agent_name=None,
            user_agent_string=None,
            response_has_content=None,
            response_mime_type=None,
            response_primary_hash=None,
            response_secondary_hash=None,
            response_status_code=None,
            **kwargs
    ):
        super(UserAgentFingerprintModel, self).__init__(**kwargs)
        self.user_agent_type = user_agent_type
        self.user_agent_name = user_agent_name
        self.user_agent_string = user_agent_string
        self.response_has_content = response_has_content
        self.response_mime_type = response_mime_type
        self.response_primary_hash = response_primary_hash
        self.response_secondary_hash = response_secondary_hash
        self.response_status_code = response_status_code

    # Static Methods

    # Class Methods

    @classmethod
    def _populate_dummy(cls, to_populate):
        from lib import WsFaker, RandomHelper
        to_populate.user_agent_type = WsFaker.get_word()
        to_populate.user_agent_name = WsFaker.get_word()
        to_populate.user_agent_string = WsFaker.get_user_agent()
        to_populate.response_has_content = RandomHelper.flip_coin()
        to_populate.response_mime_type = WsFaker.get_mime_string()
        to_populate.response_primary_hash = WsFaker.get_sha256_string()
        to_populate.response_secondary_hash = WsFaker.get_sha256_string()
        to_populate.response_status_code = WsFaker.get_http_response_status()
        return to_populate

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
