# -*- coding: utf-8 -*-
from __future__ import absolute_import

import calendar
import errno
import locale
import optparse
import re
import sys
import time
import urllib
import urllib2
from cStringIO import StringIO
from .config import ConfigManager

try:
    import json
except ImportError:
    import simplejson as json

cfg = None
options = None
config = ConfigManager.instance()

locale.setlocale(locale.LC_ALL, '')


class QueryError(Exception):
    pass


class DnsdbClient(object):
    def __init__(self, server, apikey, limit=None, http_proxy=None, https_proxy=None):
        self.server = server
        self.apikey = apikey
        self.limit = limit
        self.http_proxy = http_proxy
        self.https_proxy = https_proxy

    def query_rrset(self, oname, rrtype=None, bailiwick=None, before=None, after=None):
        if bailiwick:
            if not rrtype:
                rrtype = 'ANY'
            path = 'rrset/name/%s/%s/%s' % (quote(oname), rrtype, quote(bailiwick))
        elif rrtype:
            path = 'rrset/name/%s/%s' % (quote(oname), rrtype)
        else:
            path = 'rrset/name/%s' % quote(oname)
        return self._query(path, before, after)

    def query_rdata_name(self, rdata_name, rrtype=None, before=None, after=None):
        if rrtype:
            path = 'rdata/name/%s/%s' % (quote(rdata_name), rrtype)
        else:
            path = 'rdata/name/%s' % quote(rdata_name)
        return self._query(path, before, after)

    def query_rdata_ip(self, rdata_ip, before=None, after=None):
        path = 'rdata/ip/%s' % rdata_ip.replace('/', ',')
        return self._query(path, before, after)

    def _query(self, path, before=None, after=None):
        res = []
        url = '%s/lookup/%s' % (self.server, path)

        params = {}
        if self.limit:
            params['limit'] = self.limit
        if before and after:
            params['time_first_after'] = after
            params['time_last_before'] = before
        else:
            if before:
                params['time_first_before'] = before
            if after:
                params['time_last_after'] = after
        if params:
            url += '?{0}'.format(urllib.urlencode(params))

        req = urllib2.Request(url)
        req.add_header('Accept', 'application/json')
        req.add_header('X-Api-Key', self.apikey)

        proxy_args = {}
        if self.http_proxy:
            proxy_args['http'] = self.http_proxy
        if self.https_proxy:
            proxy_args['https'] = self.https_proxy
        proxy_handler = urllib2.ProxyHandler(proxy_args)
        opener = urllib2.build_opener(proxy_handler)

        try:
            http = opener.open(req)
            while True:
                line = http.readline()
                if not line:
                    break
                yield json.loads(line)
        except (urllib2.HTTPError, urllib2.URLError), e:
            raise QueryError, str(e), sys.exc_traceback


def quote(path):
    return urllib.quote(path, safe='')


def sec_to_text(ts):
    return time.strftime('%Y-%m-%d %H:%M:%S -0000', time.gmtime(ts))


def rrset_to_text(m):
    s = StringIO()

    try:
        if 'bailiwick' in m:
            s.write(';;  bailiwick: %s\n' % m['bailiwick'])

        if 'count' in m:
            s.write(';;      count: %s\n' % locale.format('%d', m['count'], True))

        if 'time_first' in m:
            s.write(';; first seen: %s\n' % sec_to_text(m['time_first']))
        if 'time_last' in m:
            s.write(';;  last seen: %s\n' % sec_to_text(m['time_last']))

        if 'zone_time_first' in m:
            s.write(';; first seen in zone file: %s\n' % sec_to_text(m['zone_time_first']))
        if 'zone_time_last' in m:
            s.write(';;  last seen in zone file: %s\n' % sec_to_text(m['zone_time_last']))

        if 'rdata' in m:
            for rdata in m['rdata']:
                s.write('%s IN %s %s\n' % (m['rrname'], m['rrtype'], rdata))

        s.seek(0)
        return s.read()
    finally:
        s.close()


def rdata_to_text(m):
    return '%s IN %s %s' % (m['rrname'], m['rrtype'], m['rdata'])


def parse_config(cfg_files):
    config = {}

    if not cfg_files:
        raise IOError(errno.ENOENT, 'dnsdb_query: No config files found')

    for fname in cfg_files:
        for line in open(fname):
            key, eq, val = line.strip().partition('=')
            val = val.strip('"')
            config[key] = val

    return config


def time_parse(s):
    try:
        epoch = int(s)
        return epoch
    except ValueError:
        pass

    try:
        epoch = int(calendar.timegm(time.strptime(s, '%Y-%m-%d')))
        return epoch
    except ValueError:
        pass

    try:
        epoch = int(calendar.timegm(time.strptime(s, '%Y-%m-%d %H:%M:%S')))
        return epoch
    except ValueError:
        pass

    m = re.match(r'^(?=\d)(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s?)?$', s, re.I)
    if m:
        return -1*(int(m.group(1) or 0)*604800 +  \
                int(m.group(2) or 0)*86400+  \
                int(m.group(3) or 0)*3600+  \
                int(m.group(4) or 0)*60+  \
                int(m.group(5) or 0))

    raise ValueError('Invalid time: "%s"' % s)


def epipe_wrapper(func):
    def f(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except IOError as e:
            if e.errno == errno.EPIPE:
                sys.exit(e.errno)
            raise
    return f


def enumerate_subdomains_for_domains(domains):
    """
    Enumerate subdomains for the list of domains through DNSDB.
    :param domains: A list of domains to enumerate subdomains for.
    :return: A list of domains representing subdomains found for the given domains.
    """
    to_return = set()
    for domain in domains:
        to_return = to_return.union(enumerate_subdomains_for_domain(domain))
    return list(to_return)


def enumerate_subdomains_for_domain(domain):
    """
    Enumerate subdomains for the given domain through DNSDB.
    :param domain: The domain to enumerate subdomains for.
    :return: A list of domains representing subdomains for the given domain.
    """
    to_return = set()
    for record_type in config.dns_dnsdb_record_types:
        to_return = to_return.union(enumerate_subdomains_for_domain_by_record_type(domain=domain, record_type=record_type))
    return list(to_return)


def enumerate_subdomains_for_domain_by_record_type(domain=None, record_type="A"):
    """
    Enumerate subdomains for the given domain based on the given DNS record type.
    :param domain: The domain to enumerate subdomains for.
    :param record_type: The record type to enumerate subdomains with.
    :return: A list of domains representing subdomains for the given domain found through the given
    record type.
    """
    wildcard_domain = "*.%s" % (domain,)
    client = DnsdbClient(config.dns_dnsdb_api_host, config.dns_dnsdb_api_key)
    record_type = record_type.lower()
    to_return = set()
    try:
        for result in client.query_rrset(wildcard_domain, rrtype=record_type, bailiwick=domain):
            to_add = result["rrname"]
            if to_add.endswith("."):
                to_add = to_add[:-1]
            to_return.add(to_add)
    except QueryError:
        pass
    return list(to_return)


def enumerate_domains_for_ip_address(ip_address, after=config.dns_dnsdb_ip_history_time_in_past):
    """
    Get a list of all the domains associated with the given IP address from the DNS DB API.
    :param ip_address: The IP address to retrieve domains for.
    :param after: The amount of time in seconds that DNSDB should be queried into the past to retrieve records.
    :return: A list of all the domains associated with the given IP address from the DNS DB API.
    """
    client = DnsdbClient(config.dns_dnsdb_api_host, config.dns_dnsdb_api_key)
    if after is not None:
        response = client.query_rdata_ip(ip_address, after=after)
    else:
        response = client.query_rdata_ip(ip_address)
    to_return = set()
    try:
        for result in response:
            to_add = result["rrname"]
            if to_add.endswith("."):
                to_add = to_add[:-1]
            to_return.add(to_add)
    except QueryError:
        pass
    return list(to_return)
