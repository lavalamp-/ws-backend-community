# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import from_django_model
import rest.models


WebService = from_django_model(rest.models.WebService)
WebServiceReport = from_django_model(rest.models.WebServiceReport)
WebServiceScan = from_django_model(rest.models.WebServiceScan)
