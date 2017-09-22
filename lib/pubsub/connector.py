# -*- coding: utf-8 -*-
from __future__ import absolute_import

from google.cloud import pubsub_v1
import logging
import json
import time

from ..singleton import Singleton
from ..config import ConfigManager
from ..exception import BaseWsException

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


class UnknownPubSubTypeException(BaseWsException):
    """
    This is an exception for denoting that a given pubsub type is not recognized.
    """

    message = "Unknown PubSub type."


class BasePubSubConnector(object):
    """
    This is a base class for classes that are built to interact with pubsub endpoints.
    """

    def get_topics(self):
        """
        Get a list of all of the topics in the configured PubSub.
        :return: a list of all of the topics in the configured PubSub.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def publish_message(self, topic=config.pubsub_publish_topic, message=None):
        """
        Publish the given message to the given topic.
        :param topic: The topic to publish the message to.
        :param message: The message to publish.
        :return: None.
        """
        raise NotImplementedError("Subclasses must implement this!")

    def publish_messages(self, topic=config.pubsub_publish_topic, messages=None):
        """
        Publish the given messages to the given topic.
        :param topic: The topic to publish messages to.
        :param messages: The messages to publish.
        :return: None.
        """
        return [self.publish_message(topic=topic, message=x) for x in messages]

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

    def __init__(self):
        self._publisher = None
        self._project_path = None
        self._in_topic_path = None
        self._out_topic_path = None
        self._subscriber = None
        self.__initialize_topics()
        self._subscriptions = {}
        self._received_messages = []

    def get_topics(self):
        to_return = list(self.publisher.list_topics(self.project_path))
        return [x.name for x in to_return]

    def publish_message(self, topic=config.pubsub_publish_topic, message=None):
        topic_path = self.publisher.topic_path(config.gcp_project_name, topic)
        to_publish = json.dumps(message)
        self.publisher.publish(topic_path, to_publish)

    def receive_all_messages(self, topic=config.pubsub_receive_topic):
        subscription = self.__get_subscription(topic=topic)
        to_return = []

        def callback(message):
            logger.debug("Got message from Google PubSub: %s" % message)
            to_return.append(message.data)
            message.ack()

        reader = self.subscriber.subscribe(subscription.name, callback=callback)
        time.sleep(config.pubsub_retrieve_interval)
        reader.close()
        return to_return

    def __get_subscription(self, topic=None):
        """
        Create and return the subscription associated with the given topic if
        the subscription doesn't exist, otherwise get the existing subscription.
        :param topic: The topic to subscribe to.
        :return: The subscription to the given topic.
        """
        if topic in self._subscriptions:
            return self._subscriptions[topic]
        subscribe_path = self.subscriber.subscription_path(
            config.gcp_project_name,
            topic,
        )
        topic_path = self.publisher.topic_path(config.gcp_project_name, topic)
        subscriptions = self.subscriber.list_subscriptions(topic_path)
        for subscription in subscriptions:
            if subscription.name == subscribe_path:
                self._subscriptions[topic] = subscription
                return subscription
        subscription = self.subscriber.create_subscription(
            subscribe_path,
            topic_path,
        )
        self._subscriptions[topic] = subscription
        return self._subscriptions[topic]

    def __initialize_topics(self):
        """
        Check to see if all of the necessary topics exist and create them if
        they don't.
        :return: None
        """
        topics = self.get_topics()
        if not any([x.endswith(config.pubsub_receive_topic) for x in topics]):
            logger.debug(
                "Topic %s does not exist in GCP PubSub. Creating now."
                % (config.pubsub_receive_topic,)
            )
            response = self.publisher.create_topic(self.in_topic_path)
            logger.debug(
                "Response from creating %s topic: %s."
                % (config.pubsub_receive_topic, response)
            )
        if not any([x.endswith(config.pubsub_publish_topic) for x in topics]):
            logger.debug(
                "Topic %s does not exist in GCP PubSub. Creating now."
                % (config.pubsub_publish_topic,)
            )
            response = self.publisher.create_topic(self.out_topic_path)
            logger.debug(
                "Response from creating %s topic: %s."
                % (config.pubsub_publish_topic, response)
            )
        logger.debug("GCP PubSub topics initialized.")

    @property
    def in_topic_path(self):
        """
        Get the topic path to use to retrieve messages from.
        :return: the topic path to use to retrieve messages from.
        """
        if self._in_topic_path is None:
            self._in_topic_path = self.publisher.topic_path(
                config.gcp_project_name,
                config.pubsub_receive_topic,
            )
        return self._in_topic_path

    @property
    def out_topic_path(self):
        """
        Get the topic path to use to send messages to.
        :return: the topic path to use to send messages to.
        """
        if self._out_topic_path is None:
            self._out_topic_path = self.publisher.topic_path(
                config.gcp_project_name,
                config.pubsub_publish_topic,
            )
        return self._out_topic_path

    @property
    def project_path(self):
        """
        Get the project path to use to communicate with Google PubSub.
        :return: the project path to use to communicate with Google PubSub.
        """
        if self._project_path is None:
            self._project_path = self.publisher.project_path(config.gcp_project_name)
        return self._project_path

    @property
    def publisher(self):
        """
        Get the publisher to use to communicate with the Google PubSub API.
        :return: the publisher to use to communicate with the Google PubSub API.
        """
        if self._publisher is None:
            self._publisher = pubsub_v1.PublisherClient()
        return self._publisher

    @property
    def subscriber(self):
        """
        Get the subscriber to use to receive messages from Google PubSub.
        :return: the subscriber to use to receive messages from Google PubSub.
        """
        if self._subscriber is None:
            self._subscriber = pubsub_v1.SubscriberClient()
        return self._subscriber

    @property
    def subscriptions(self):
        """
        Get a dictionary mapping topics to their related subscriptions.
        :return: a dictionary mapping topics to their related subscriptions.
        """
        return self._subscriptions


def get_pubsub_connector():
    """
    Get the PubSub connector that should be used to send and receive messages from the pubsub.
    :return: The PubSub connector that should be used to send and receive messages from the pubsub.
    """
    if config.pubsub_connector_type == "gcp":
        return GooglePubSubConnector.instance()
    else:
        raise UnknownPubSubTypeException("Did not recognize PubSub type of %s." % config.pubsub_connector_type)
