# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models
from .base import from_django_model


Order = from_django_model(rest.models.Order)
OrderDomainName = from_django_model(rest.models.OrderDomainName)
OrderNetwork = from_django_model(rest.models.OrderNetwork)
