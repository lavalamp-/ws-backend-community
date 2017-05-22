# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging, os
from lib.config import ConfigManager
from lib.endpoint import WebFingerprint
from lib.grequests import GRequestsHelper
from lib.parsing.wrappers import UrlWrapper

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


class WebContentDiscoveryHelper(object):
    """
    This class contains helper methods for content discovery
    """

    # Class Members

    #This is the local file path to the files with known common url paths
    _content_discovery_db = 'lib/content_discovery/db'

    #This is the interal GRequestHelper that sends the requests while discovering
    _grequest_helper = None

    # Instantiation
    def __init__(self):
        self._grequest_helper = GRequestsHelper()

    # Static Methods

    # Class Methods

    #Public Methods
    def discover_all_urls(self, base_url):
        """
        This is used to discover all valid urls we can find from the base_url
        This will recursively load all files from the content_discovery/db folders, and use their contents
            to  build posible url paths
        :param base_url: The base url of the web application
        :return: A populated WebFingerprint
        """

        #Generate all of the urls to attempt to discover
        urls_to_request = []
        all_db_file_names = self._all_db_file_names()
        for file_name in all_db_file_names:
            lines = self._get_lines_from_file_name(file_name)
            urls_to_request.extend(self._get_urls_from_lines(base_url, lines))

        #Send the requests
        responses = self._grequest_helper.send_requests('get', urls_to_request)
        fingerprint = WebFingerprint(base_url)
        fingerprint.analyze_responses(responses)
        return fingerprint


    def discover_urls(self, base_url, language):
        """
        This is used to discover all valid urls, based on the assumed language provided
        :param base_url: This is the base url of the web application
        :param language: This is the assumed language that will controll what paths are attempted
        :return: A populated WebFingerprint
        """
        # Generate all of the urls to attempt to discover
        urls_to_request = []
        all_file_names = []

        all_db_common_file_names = self._all_db_common_file_names()
        all_db_language_file_names = self._all_db_language_file_names(language)
        all_file_names.extend(all_db_common_file_names)
        all_file_names.extend(all_db_language_file_names)

        for file_name in all_file_names:
            lines = self._get_lines_from_file_name(file_name)
            urls_to_request.extend(self._get_urls_from_lines(base_url, lines))

        # Send the requests
        responses = self._grequest_helper.send_requests('get', urls_to_request)
        fingerprint = WebFingerprint(base_url)
        fingerprint.analyze_responses(responses)
        return fingerprint

    # Protected Methods
    def _get_urls_from_lines(self, base_url, lines):
        """
        This will return a list of UrlWrapper, created from the base url and the list of lines
        :param base_url: This should be a root url
        :param lines:  This should be a list of lines, that will be added to our base path
        :return: A list of UrlWrappers
        """
        result = []
        for line in lines:
            clean_line = line.strip()
            url_wrapper = UrlWrapper(base_url + clean_line)
            result.append(url_wrapper)
        return result


    def _get_lines_from_file_name(self, file_name):
        """
        This will return a list of lines from the provided file
        :param wsfile: The file to get lines from
        :return: A list of lines from the provided file
        """
        result = []
        with open(file_name) as f:
            lines = f.readlines()
            result.extend(lines)
        return result


    def _all_db_file_names(self):
        """
        This will return all of the file names that the content_discovery/db folder contains
        :return: The list of all db file names
        """
        file_names = []
        for (dirpath, dirnames, filenames) in os.walk(self._content_discovery_db):
            for file_name in filenames:
                file_names.append(dirpath + '/' + file_name)
        return file_names


    def _all_db_common_file_names(self):
        """
        This will return all of the root file names that the content_discovery/db folder contains
        :return: The list of all the common db file names
        """
        file_names = [self._content_discovery_db + '/' + f for f in os.listdir(self._content_discovery_db) if os.path.isfile(self._content_discovery_db + '/' + f)]
        return file_names


    def _all_db_language_file_names(self, language):
        """
        This will return all of the file names that the content_discovery/db language folder contains
        :return: The list of all the  db file names for that language
        """
        directory_path = self._content_discovery_db + '/' + language
        file_names = [directory_path + '/' + f for f in os.listdir(directory_path) if os.path.isfile(directory_path + '/' + f)]
        return file_names

    # Private Methods

    # Properties

    # Representation and Comparison
