# -*- coding: utf-8 -*-
from __future__ import absolute_import

import django_filters

import rest.models


class PaymentTokenFilter(django_filters.rest_framework.FilterSet):
    """
    This is a filter set for the PaymentToken rest model.
    """

    name = django_filters.CharFilter(name="name", lookup_expr="contains")
    token_type = django_filters.CharFilter(name="token_type", lookup_expr="contains")
    can_be_charged = django_filters.BooleanFilter(name="can_be_charged")

    class Meta:
        model = rest.models.PaymentToken
        fields = ["name", "token_type", "can_be_charged"]

