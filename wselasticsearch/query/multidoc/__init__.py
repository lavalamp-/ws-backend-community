# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .dns import (
    DomainNameMultidocQuery,
    DomainNameScanMultidocQuery,
)

from .network import (
    IpAddressScanMultidocQuery,
)

from .services import (
    NetworkServiceScanMultidocQuery,
)

from .ssl import (
    SslSupportRelatedMultidocQuery,
)

from .web import (
    WebResourceMultidocQuery,
    WebScanMultidocQuery,
)
