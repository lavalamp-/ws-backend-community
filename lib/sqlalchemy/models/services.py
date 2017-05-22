# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import from_django_model
import rest.models


NetworkService = from_django_model(rest.models.NetworkService)
NetworkServiceScan = from_django_model(rest.models.NetworkServiceScan)
