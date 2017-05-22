# -*- coding: utf-8 -*-
from __future__ import absolute_import
from datetime import datetime, timedelta
from wselasticsearch.query import LoginAttemptQuery
from wselasticsearch.helper import ElasticsearchHelper
from lib.config import ConfigManager

es_helper = ElasticsearchHelper.instance()
config = ConfigManager.instance()

def get_login_attempts_for_ip_address_within_threshold(ip_address=None, index=None):
    """
    This searches for all login attempts from the provided ip_address
    :param ip_address: The Ip Address to search for
    :param index: The index to search in.
    :return:
    """

    start_time = datetime.now() - timedelta(minutes=config.recaptcha_timeout_minutes)
    end_time = datetime.now() + timedelta(minutes=config.recaptcha_timeout_minutes)

    query = LoginAttemptQuery()
    query.must_by_term(key="ip_address", value=ip_address)
    query.must_by_datetime_range(key="attempt_date", r_from_datetime=start_time, r_to_datetime=end_time)
    return query.search(index=index)