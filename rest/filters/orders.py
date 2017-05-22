# -*- coding: utf-8 -*-
from __future__ import absolute_import

import django_filters

import rest.models


class OrderFilter(django_filters.rest_framework.FilterSet):
    """
    This is a filter set for the Order rest model.
    """

    min_order_cost = django_filters.NumberFilter(name="order_cost", lookup_expr="gte")
    max_order_cost = django_filters.NumberFilter(name="order_cost", lookup_expr="lte")
    has_been_charged = django_filters.BooleanFilter(name="has_been_charged")

    class Meta:
        model = rest.models.Order
        fields = ["min_order_cost", "max_order_cost", "has_been_charged"]
