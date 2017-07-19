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

    def get(self, *args, **kwargs):
        """
        Get a single instance of a report for the requested data type.
        """
        return super(BaseElasticsearchSingleMappedAPIView, self).get(*args, **kwargs)


class BaseElasticsearchManyMappedAPIView(BaseElasticsearchManyMappedAPIViewMixin, APIView):
    """
    This is a base class for all Elasticsearch APIView classes that query Elasticsearch models based
    on database models and return multiple results.
    """

    def get(self, *args, **kwargs):
        """
        Get all of the reports of the requested data type associated with the referenced parent instance.
        """
        return super(BaseElasticsearchManyMappedAPIView, self).get(*args, **kwargs)


class BaseElasticsearchAnalyticsAPIView(BaseElasticsearchAnalyticsAPIViewMixin, APIView):
    """
    This is a base class for all Elasticsearch APIView classes that query Elasticsearch models based
    on database models and return statistical data.
    """

    def get(self, *args, **kwargs):
        """
        Get analytical data about all of the given type of report associated with the referenced parent instance.
        """
        return super(BaseElasticsearchAnalyticsAPIView, self).get(*args, **kwargs)


class BaseElasticsearchRelatedAPIView(BaseElasticsearchRelatedAPIViewMixin, APIView):
    """
    This is a base class for all Elasticsearch APIView classes that query Elasticsearch models that
    are related to another Elasticsearch model.
    """

    def get(self, *args, **kwargs):
        """
        Get a single instance of a report for the requested data type related to the referenced parent instance.
        """
        return super(BaseElasticsearchRelatedAPIViewMixin, self).get(*args, **kwargs)
