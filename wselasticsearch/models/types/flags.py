# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseComplexElasticsearchType
from .basic import *


class FlagElasticsearchType(BaseComplexElasticsearchType):
    """
    This is an Elasticsearch type for representing a flag.
    """

    def to_dict(self):
        return {
            "type": self.type,
            "properties": {
                "flag_name": KeywordElasticsearchType().to_dict(),
                "flag_tag": KeywordElasticsearchType().to_dict(),
                "flag_weight": IntElasticsearchType().to_dict(),
            }
        }
