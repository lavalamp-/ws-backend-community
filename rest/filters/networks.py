# -*- coding: utf-8 -*-
from __future__ import absolute_import

import django_filters

import rest.models


class NetworkFilter(django_filters.rest_framework.FilterSet):
    """
    This is a filter set for the Network rest model.
    """

    min_mask_length = django_filters.NumberFilter(name="mask_length", lookup_expr="gte")
    max_mask_length = django_filters.NumberFilter(name="mask_length", lookup_expr="lte")
    name = django_filters.CharFilter(name="name", lookup_expr="contains")
    address = django_filters.CharFilter(name="address", lookup_expr="contains")
    search = django_filters.CharFilter(name="name", lookup_expr="contains")

    class Meta:
        model = rest.models.Network
        fields = ["min_mask_length", "max_mask_length", "name", "address", "search"]
