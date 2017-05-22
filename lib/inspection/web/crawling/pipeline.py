# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from lib import ConfigManager
from .item import HttpTransaction, HttpResource, HtmlWebResourceItem, GenericWebResourceItem
from .exception import UnsupportedItemWriteError
import json

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


class WsLocalStoragePipeline(object):
    """
    This is a Scrapy pipeline for writing scraped items to a local file.
    """

    # Class Members

    # Instantiation

    def __init__(self):
        self._local_file_path = None
        self._item_buffer = []

    # Static Methods

    # Class Methods

    # Public Methods

    def close_spider(self, spider):
        """
        This method is called when a Scrapy spider is closed, and ensures that any remaining
        objects in the item buffer are written to disk.
        :param spider: The spider that caused this method to be called.
        :return: None
        """
        if len(self.item_buffer) > 0:
            self.__write_buffer_to_disk()

    def open_spider(self, spider):
        """
        This method is called when a Scrapy spider is opened, and sets the local filesystem
        path to write objects to.
        :param spider: The spider that caused this method to be called.
        :return: None
        """
        self._local_file_path = spider.file_path

    def process_item(self, item, spider):
        """
        Process the given Scrapy item for writing to the local filesystem.
        :param item: The item to process.
        :param spider: The spider that resulted in this method being called.
        :return: None
        """
        self._item_buffer.append(item)
        if len(self._item_buffer) >= config.crawling_local_storage_buffer_size:
            self.__write_buffer_to_disk()

    # Protected Methods

    # Private Methods

    def __write_buffer_to_disk(self):
        """
        Write all of the items found in the item buffer to self.local_file_path.
        :return: None
        """
        logger.debug(
            "Now writing buffer of length %s to disk at %s."
            % (len(self.item_buffer), self.local_file_path)
        )
        with open(self.local_file_path, "a+") as f:
            for item in self.item_buffer:
                self.__write_item_to_file(item=item, file_descriptor=f)
        self._item_buffer = []
        logger.debug(
            "Item buffer written to %s successfully."
            % (self.local_file_path,)
        )

    def __write_item_to_file(self, item=None, file_descriptor=None):
        """
        Write the contents of the given Scrapy item to the given file descriptor.
        :param item: The item to write out.
        :param file_descriptor: The file descriptor to write to.
        :return: None
        """
        if isinstance(item, HttpResource):
            to_write = "HttpResource,%s\n" % (json.dumps(dict(item)),)
        elif isinstance(item, HttpTransaction):
            to_write = "HttpTransaction,%s\n" % (json.dumps(dict(item)),)
        elif isinstance(item, HtmlWebResourceItem):
            to_write = "HtmlWebResourceItem,%s\n" % (json.dumps(dict(item)),)
        elif isinstance(item, GenericWebResourceItem):
            to_write = "GenericWebResourceItem,%s\n" % (json.dumps(dict(item)),)
        else:
            raise UnsupportedItemWriteError(
                "No support for item of type %s."
                % (item.__class__.__name__,)
            )
        file_descriptor.write(to_write)

    # Properties

    @property
    def item_buffer(self):
        """
        Get the list of Scrapy items that are pending write to the local filesystem.
        :return: the list of Scrapy items that are pending write to the local filesystem.
        """
        return self._item_buffer

    @property
    def local_file_path(self):
        """
        Get the local file path where results are written to.
        :return: the local file path where results are written to.
        """
        return self._local_file_path

    # Representation and Comparison
