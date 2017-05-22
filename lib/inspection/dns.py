# -*- coding: utf-8 -*-
from __future__ import absolute_import

from berserker_resolver import Resolver
import random

from .base import BaseInspector
import logging
from lib import ConfigManager, FilesystemHelper, Singleton

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


def get_resolvers():
    """
    Get a list of IP addresses to use as DNS resolvers.
    :return: A list of IP addresses to use as DNS resolvers.
    """
    contents = FilesystemHelper.get_file_contents(path=config.files_dns_resolvers_path)
    to_return = [x.strip() for x in contents.strip().split("\n")]
    to_return = filter(lambda x: not x.startswith("#"), to_return)
    return random.sample(to_return, len(to_return)/2)


@Singleton
class WebSightResolver(Resolver):
    """
    This is a berserker_resolver wrapper subclass that implements singleton, meaning
    that we don't have to create a new resolver every time that a new task needs to resolve
    domain names.
    """

    def __init__(self):
        super(WebSightResolver._decorated, self).__init__()
        self.nameservers = get_resolvers()
        self.tries = config.dns_resolver_tries
        self.timeout = config.dns_resolver_timeout


class DomainInspector(BaseInspector):
    """
    This class contains methods for inspecting a domain name.
    """

    # Class Members

    # Instantiation

    def __init__(self, domain_name):
        super(DomainInspector, self).__init__()
        self._domain_name = domain_name
        self._resolver = None

    # Static Methods

    # Class Methods

    # Public Methods

    def get_record(self, record_type):
        """
        Perform a DNS lookup for self.domain_name for the given record type and return a list containing
        the record contents.
        :param record_type: The record type to look up.
        :return: A list containing the record contents for the DNS lookup.
        """
        self.resolver.qname = record_type
        result = self.resolver.resolve([self.domain_name])
        if self.domain_name not in result:
            return []
        else:
            to_return = []
            for record in result[self.domain_name]:
                to_return.append(record.to_text())
            return to_return

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def domain_name(self):
        """
        Get the domain names that this inspector is configured to inspect.
        :return: the domain names that this inspector is configured to inspect.
        """
        return self._domain_name

    @property
    def inspection_target(self):
        return self.domain_name

    @property
    def resolver(self):
        """
        Get the berserker resolver to use to query DNS records.
        :return: the berserker resolver to use to query DNS records.
        """
        if self._resolver is None:
            self._resolver = WebSightResolver.instance()
        return self._resolver

    # Representation and Comparison
