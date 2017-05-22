# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
from lib.config import ConfigManager

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


class WebFingerprint(object):

    # Class Members

    #This is a list of all supported languages to discover
    _all_languages = [
        'csharp',
        'go',
        'groovy',
        'java',
        'js',
        'perl',
        'php',
        'python',
        'ruby',
        'misc'
    ]

    _language = None
    _framework = None
    _base_url = None
    _valid_urls = []
    _invalid_urls = []
    _resource_urls = []


    # Instantiation
    def __init__(self, base_url):
        self._base_url = base_url
        pass

    # Static Methods

    # Class Methods

    # Public Methods
    def analyze_responses(self, responses):
        """
        This will populate the fingerprint, based on a list of responses
        :param responses: The completed responses to analyze
        """
        valid_responses = [ r for r in responses if r is not None and r.status_code == 200]
        valid_urls = [ vr.url for vr in valid_responses ]
        for valid_url in valid_urls:
            if valid_url not in self._valid_urls:
                self._valid_urls.append(valid_url)

        invalid_responses = [ r for r in responses if r is not None and r.status_code != 200]
        invalid_urls = [ vr.url for vr in invalid_responses ]
        for invalid_url in invalid_urls:
            if invalid_url not in self._invalid_urls:
                self._invalid_urls.append(invalid_url)

        #TODO: Discover Language and Framework based on valid & invalid urls
        pass


    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
    def __str__(self):
        """ This returns a string representation of the fingerprint """
        return '< WebFingerprint - %s >' % (self._base_url)

