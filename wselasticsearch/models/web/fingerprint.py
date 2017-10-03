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

    user_agent_type = KeywordElasticsearchType(
        help_text="A string depicting the type of user agent that this fingerprint checked for.",
    )
    user_agent_name = KeywordElasticsearchType(
        help_text="The name of the user agent that this fingerprint checked for.",
    )
    user_agent_string = KeywordElasticsearchType(
        help_text="The contents of the user agent that were used during this fingerprint check.",
    )
    response_has_content = BooleanElasticsearchType(
        help_text="Whether or not the HTTP response for the fingerprinting request returned any content.",
    )
    response_mime_type = KeywordElasticsearchType(
        help_text="The MIME type returned by the HTTP response for the fingerprinting request.",
    )
    response_primary_hash = KeywordElasticsearchType(
        help_text="A cryptographic hash of the response content returned for the fingerprinting request.",
    )
    response_secondary_hash = KeywordElasticsearchType(
        help_text="A secondary hash representing the content returned by the HTTP "
                  "fingerprinting response (contents of secondary hash depend on MIME type).",
    )
    response_status_code = IntElasticsearchType(
        help_text="The HTTP status code returned in response to the fingerprinting HTTP request.",
    )

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
