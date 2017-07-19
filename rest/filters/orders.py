# -*- coding: utf-8 -*-
from __future__ import absolute_import

import django_filters

import rest.models


class OrderFilter(django_filters.rest_framework.FilterSet):
    """
    This is a filter set for the Order rest model.
    """

    has_been_placed = django_filters.BooleanFilter(
        name="has_been_placed",
        help_text="Whether or not the order has been placed.",
    )

    class Meta:
        model = rest.models.Order
        fields = ["has_been_placed"]
