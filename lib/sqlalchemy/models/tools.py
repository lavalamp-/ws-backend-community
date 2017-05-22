# -*- coding: utf-8 -*-
from __future__ import absolute_import

import rest.models

from .base import from_django_model

NmapConfig = from_django_model(rest.models.NmapConfig)
ZmapConfig = from_django_model(rest.models.ZmapConfig)
