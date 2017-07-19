# -*- coding: utf-8 -*-
from __future__ import absolute_import

import django_filters

import rest.models


class OrganizationFilter(django_filters.rest_framework.FilterSet):
    """
    This is a filter set for the Organization rest model.
    """

    name = django_filters.CharFilter(
        name="name",
        lookup_expr="contains",
        help_text="The name of the organization to search for.",
    )
    search = django_filters.CharFilter(
        name="name",
        lookup_expr="contains",
        help_text="A term to search for within all organizations."
    )

    class Meta:
        model = rest.models.Organization
        fields = ["name", "search"]
