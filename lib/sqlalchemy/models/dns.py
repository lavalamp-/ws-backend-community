# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models
from .base import from_django_model


DomainName = from_django_model(rest.models.DomainName)
DomainNameScan = from_django_model(rest.models.DomainNameScan)
DnsRecordType = from_django_model(rest.models.DnsRecordType)
