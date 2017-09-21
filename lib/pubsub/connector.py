# -*- coding: utf-8 -*-
from __future__ import absolute_import

from ..singleton import Singleton
from ..config import ConfigManager
from ..exception import BaseWsException

config = ConfigManager.instance()


class UnknownPubSubTypeException(BaseWsException):
    """
    This is an exception for denoting that a given pubsub type is not recognized.
    """

    message = "Unknown PubSub type."


class BasePubSubConnector(object):
    """
    This is a base class for classes that are built to interact with pubsub endpoints.
    """

    def publish(self, topic=config.pubsub_publish_topic, message=None):
        """
        Publish the given message to the given topic.
        :param topic: The topic to publish the message to.
        :param message: The message to publish.
        :return: True if the message was published successfully, False otherwise.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def receive_all_messages(self, topic=config.pubsub_receive_topic):
        """
        Receive all of the messages that are currently available for the given topic.
        :param topic: The topic that messages should be retrieved for.
        :return: A list containing the messages that were retrieved from the given topic.
        """
        raise NotImplementedError("Subclasses must implement this!")


@Singleton
class GooglePubSubConnector(BasePubSubConnector):
    """
    This is a PubSub connector class for connecting to the Google Cloud Platform pubsub.
    """

    def publish(self, topic=config.pubsub_publish_topic, message=None):
        pass

    def receive_all_messages(self, topic=config.pubsub_receive_topic):
        pass


def get_pubsub_connector():
    """
    Get the PubSub connector that should be used to send and receive messages from the pubsub.
    :return: The PubSub connector that should be used to send and receive messages from the pubsub.
    """
    if config.pubsub_connector_type == "gcp":
        return GooglePubSubConnector.instance()
    else:
        raise UnknownPubSubTypeException("Did not recognize PubSub type of %s." % config.pubsub_connector_type)
