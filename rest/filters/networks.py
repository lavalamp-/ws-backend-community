# -*- coding: utf-8 -*-
from __future__ import absolute_import

import django_filters

import rest.models


class NetworkFilter(django_filters.rest_framework.FilterSet):
    """
    This is a filter set for the Network rest model.
    """

    min_mask_length = django_filters.NumberFilter(
        name="mask_length",
        lookup_expr="gte",
        help_text="The minimum mask length to search for."
    )
    max_mask_length = django_filters.NumberFilter(
        name="mask_length",
        lookup_expr="lte",
        help_text="The maximum mask length to search for."
    )
    name = django_filters.CharFilter(
        name="name",
        lookup_expr="contains",
        help_text="The name of the network to search for.",
    )
    address = django_filters.CharFilter(
        name="address",
        lookup_expr="contains",
        help_text="The address of the network to search for.",
    )
    search = django_filters.CharFilter(
        name="name",
        lookup_expr="contains",
        help_text="A term to search for within the referenced networks.",
    )

    class Meta:
        model = rest.models.Network
        fields = ["min_mask_length", "max_mask_length", "name", "address", "search"]
