# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseComplexElasticsearchType
from .basic import *


class UserAgentFingerprintElasticsearchType(BaseComplexElasticsearchType):
    """
    This is an Elasticsearch type for representing a user agent fingerprint.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def to_dict(self):
        return {
            "type": self.type,
            "properties": {
                "user_agent_type": KeywordElasticsearchType().to_dict(),
                "user_agent_name": KeywordElasticsearchType().to_dict(),
                "response_has_content": BooleanElasticsearchType().to_dict(),
                "response_mime_type": KeywordElasticsearchType().to_dict(),
                "response_primary_hash": KeywordElasticsearchType().to_dict(),
                "response_secondary_hash": KeywordElasticsearchType().to_dict(),
                "response_status_code": IntElasticsearchType().to_dict(),
            }
        }

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class HtmlFormElasticsearchType(BaseComplexElasticsearchType):
    """
    This is an Elasticsearch type for representing an HTML form.
    """

    # Class Members

    # Instantiation

    def __init__(self, **kwargs):
        super(HtmlFormElasticsearchType, self).__init__(**kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    def to_dict(self):
        return {
            "type": self.type,
            "properties": {
                "has_action": BooleanElasticsearchType().to_dict(),
                "action": KeywordElasticsearchType().to_dict(),
                "resolved_action": KeywordElasticsearchType().to_dict(),
                "has_method": BooleanElasticsearchType().to_dict(),
                "method": KeywordElasticsearchType().to_dict(),
                "inputs": HtmlInputElasticsearchType().to_dict(),
                "https_submission": BooleanElasticsearchType().to_dict(),
                "has_password_input": BooleanElasticsearchType().to_dict(),
                "has_email_input": BooleanElasticsearchType().to_dict(),
                "has_password_name": BooleanElasticsearchType().to_dict(),
            }
        }

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class HtmlInputElasticsearchType(BaseComplexElasticsearchType):
    """
    This is an Elasticsearch type for representing an HTML input field.
    """

    # Class Members

    # Instantiation

    def __init__(self, **kwargs):
        super(HtmlInputElasticsearchType, self).__init__(**kwargs)

    # Static Methods

    # Class Methods

    # Public Methods

    def to_dict(self):
        return {
            "type": self.type,
            "properties": {
                "has_type": BooleanElasticsearchType().to_dict(),
                "type": KeywordElasticsearchType().to_dict(),
                "has_name": BooleanElasticsearchType().to_dict(),
                "name": KeywordElasticsearchType().to_dict(),
                "has_value": BooleanElasticsearchType().to_dict(),
                "value": KeywordElasticsearchType().to_dict(),
            },
        }

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
