# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from ..config import ConfigManager
from ..singleton import Singleton
from .connector import get_pubsub_connector

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


@Singleton
class PubSubManager(object):
    """
    This class contains methods for interacting with the PubSub that Web Sight is configured to communicate
    with.
    """

    def __init__(self):
        self._connector = None

    def process_all_outstanding_messages(self, topic=config.pubsub_receive_topic):
        """
        Process all of the messages currently found within the given pubsub topic.
        :param topic: The topic to retrieve messages for.
        :return: None
        """
        for message in self.connector.receive_all_messages(topic=topic):
            self.__process_message(message)

    def __process_message(self, message):
        """
        Process the given message as retrieved from a pubsub.
        :param message: The message to process.
        :return: None
        """
        message_type = message.get("message_type", None)
        if message_type is None:
            logger.debug(
                "Message did not have a message_type: %s."
                % (message,)
            )
            return
        if message_type == "scan":
            self.__process_scan_message(message)
        else:
            logger.warning(
                "Unrecognized message type of %s. Message was %s."
                % (message_type, message)
            )

    def __process_scan_message(self, message):
        """
        Process the contents of the given message as a scan message.
        :param message: The scan message to process.
        :return: None
        """
        pass

    @property
    def connector(self):
        """
        Get the pubsub connector to use to communicate with the configured PubSub.
        :return: the pubsub connector to use to communicate with the configured PubSub.
        """
        if self._connector is None:
            self._connector = get_pubsub_connector()
        return self._connector
