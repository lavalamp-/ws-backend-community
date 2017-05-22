# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import from_django_model
import rest.models


Network = from_django_model(rest.models.Network)
IpAddress = from_django_model(rest.models.IpAddress)
IpAddressScan = from_django_model(rest.models.IpAddressScan)
