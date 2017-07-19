# -*- coding: utf-8 -*-
from __future__ import absolute_import

import django_filters

import rest.models


class DomainNameFilter(django_filters.rest_framework.FilterSet):
    """
    This is a filter set for the DomainName rest model.
    """

    name = django_filters.CharFilter(
        name="name",
        lookup_expr="contains",
        help_text="The contents of a domain to search for.",
    )
    search = django_filters.CharFilter(
        name="name",
        lookup_expr="contains",
        help_text="The contents of a domain to search for.",
    )

    class Meta:
        model = rest.models.DomainName
        fields = ["name", "search"]
