# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWrapper
from lib import WsIntrospectionHelper
from .exception import InvalidScrapyResultError, UnsupportedScrapyResultError
import json


class ScrapyResultWrapper(BaseWrapper):
    """
    This is a wrapper class for processing the contents of a file containing Scrapy results.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def iter_es_models(
            self,
            web_service_scan=None,
            web_service_scan_uuid=None,
            db_session=None,
            site_url=None,
    ):
        """
        Iterate over all of the results found in the file referenced by this wrapper class and return
        Elasticsearch model objects representing the gathered data.
        :param web_service_scan: The web service scan model that the Scrapy results were collected on behalf
        of.
        :param web_service_scan_uuid: The UUID of the web service scan model that the Scrapy results were
        collected on behalf of.
        :param db_session: A SQLAlchemy session.
        :param site_url: The URL of the site that was inspected.
        :return: A generator that yields Elasticsearch model objects reflecting the data in the
        gathered Scrapy results.
        """
        from lib.parsing import UrlWrapper
        from lib.inspection import HtmlWebResourceItem
        from lib.sqlalchemy import WebServiceScan
        if web_service_scan is None:
            web_service_scan = WebServiceScan.by_uuid(uuid=web_service_scan_uuid, db_session=db_session)
        if not isinstance(site_url, UrlWrapper):
            site_url = UrlWrapper(site_url)
        for cur_result in self.iter_results():
            if isinstance(cur_result, HtmlWebResourceItem):
                yield cur_result.to_es_model(model=web_service_scan, site_url=site_url)
            else:
                yield cur_result.to_es_model(model=web_service_scan)

    def iter_results(self):
        """
        Iterate over the results of the Scrapy results file, returning the result items one
        at a time.
        :return: A generator for iterating over the contents of the Scrapy results file.
        """
        contents_split = [x.strip() for x in self.wrapped_data.split("\n")]
        class_map = self.__get_item_class_map()
        for entry in contents_split:
            if "," not in entry:
                raise InvalidScrapyResultError(
                    "No comma found in entry: %s."
                    % (entry,)
                )
            class_name = entry[:entry.find(",")]
            item_string = entry[entry.find(",") + 1:]
            if class_name not in class_map:
                raise UnsupportedScrapyResultError(
                    "Item with name of %s is not a supported Scrapy item."
                    % (class_name,)
                )
            yield class_map[class_name](json.loads(item_string))

    # Protected Methods

    # Private Methods

    def __get_item_class_map(self):
        """
        Get a dictionary that maps a class name as a string to the class for all of the item
        classes defined in the crawling module.
        :return: A dictionary that maps a class name as a string to the class for all of the item
        classes defined in the crawling module.
        """
        item_tuples = WsIntrospectionHelper.get_scrapy_item_classes()
        return {name: item_class for name, item_class in item_tuples}

    # Properties

    @property
    def wrapped_type(self):
        return "Scrapy results"

    # Representation and Comparison
