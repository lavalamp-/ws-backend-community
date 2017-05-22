# -*- coding: utf-8 -*-
from __future__ import absolute_import

from scrapy.core.downloader.contextfactory import ScrapyClientContextFactory
from lib import ConfigManager
import os

config = ConfigManager.instance()


class WebSightClientContextFactory(ScrapyClientContextFactory):
    """
    This is a special client context factory that establishes SSL/TLS connections with a pre-defined
    hostname instead of relying on the hostname from HTTP(S) requests.
    """

    def __init__(self, *args, **kwargs):
        self._hostname = None
        super(WebSightClientContextFactory, self).__init__(*args, **kwargs)

    def creatorForNetloc(self, hostname, port):
        return super(WebSightClientContextFactory, self).creatorForNetloc(self.hostname, port)

    @property
    def hostname(self):
        """
        Get the hostname that should be submitted alongside all requests that the Scrapy crawler sends.
        :return: The hostname that should be submitted alongside all requests that the Scrapy crawler sends.
        """
        if self._hostname is None:
            self._hostname = config.globals["%s-hostname" % (os.getpid(),)]
        return self._hostname


def get_context_factory_for_hostname(input_hostname):
    """
    Create and return an anonymous client context factory class that will open SSL/TLS
    connections with the given hostname.
    :param input_hostname: The hostname to request.
    :return: An anonymous client context factory class that will open SSL/TLS connections with
    the given hostname.
    """
    class Temporary(WebSightClientContextFactory):
        hostname = input_hostname
    return Temporary
