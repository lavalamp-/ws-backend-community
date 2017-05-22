# -*- coding: utf-8 -*-
from __future__ import absolute_import

from rest_framework.views import APIView

from .mixin import BaseElasticsearchManyMappedAPIViewMixin, BaseElasticsearchAnalyticsAPIViewMixin, \
    BaseElasticsearchSingleMappedAPIViewMixin, BaseElasticsearchRelatedAPIViewMixin


class BaseElasticsearchSingleMappedAPIView(BaseElasticsearchSingleMappedAPIViewMixin, APIView):
    """
    This is a base class for all Elasticsearch APIView classes that query Elasticsearch models based
    on database models and return a single result.
    """


class BaseElasticsearchManyMappedAPIView(BaseElasticsearchManyMappedAPIViewMixin, APIView):
    """
    This is a base class for all Elasticsearch APIView classes that query Elasticsearch models based
    on database models and return multiple results.
    """


class BaseElasticsearchAnalyticsAPIView(BaseElasticsearchAnalyticsAPIViewMixin, APIView):
    """
    This is a base class for all Elasticsearch APIView classes that query Elasticsearch models based
    on database models and return statistical data.
    """


class BaseElasticsearchRelatedAPIView(BaseElasticsearchRelatedAPIViewMixin, APIView):
    """
    This is a base class for all Elasticsearch APIView classes that query Elasticsearch models that
    are related to another Elasticsearch model.
    """
