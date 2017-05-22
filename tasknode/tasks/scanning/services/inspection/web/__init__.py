# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .analysis import (
    analyze_web_service_scan,
    create_report_for_web_service_scan,
    update_web_service_report_for_organization,
    update_latest_web_service_reports_for_organization,
)

from .base import (
    apply_flag_to_web_service_scan,
    apply_flags_to_web_service_scan,
    inspect_http_service,
    inspect_https_service,
    retrieve_landing_resource_for_web_service,
    scan_web_service,
    update_web_service_scan_completed,
    update_web_service_scan_elasticsearch,
    update_web_service_scanning_status,
)

from .crawling import (
    crawl_web_service,
)

from .fingerprinting import (
    enumerate_user_agent_fingerprints_for_web_service,
    get_user_agent_fingerprint_for_web_service,
)

from .imaging import (
    screenshot_web_service,
    screenshot_web_service_url,
)

from .virtualhost import (
    assess_virtual_host_fingerprints,
    discover_virtual_hosts_for_web_service,
    fingerprint_virtual_host,
    fingerprint_virtual_hosts,
)
