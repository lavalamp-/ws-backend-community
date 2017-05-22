# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from lib import initialize_tasknode_logger

from .app import (
    websight_app,
)

logger = logging.getLogger(__name__)
initialize_tasknode_logger(logger)
