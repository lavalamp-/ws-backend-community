# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models

from .base import from_django_model

Organization = from_django_model(rest.models.Organization)
OrganizationConfig = from_django_model(rest.models.OrganizationConfig)
OrganizationNetworkScan = from_django_model(rest.models.OrganizationNetworkScan)
ScanPort = from_django_model(rest.models.ScanPort)
