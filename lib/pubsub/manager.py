# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from celery import group

from ..config import ConfigManager
from ..singleton import Singleton
from .connector import get_pubsub_connector
from ..wsregex import RegexLib

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
        self._targets = {}
        self._errors = []
        self._tasks = []
        self._messages = []

    def process_all_outstanding_messages(self, topic=config.pubsub_receive_topic):
        """
        Process all of the messages currently found within the given pubsub topic.
        :param topic: The topic to retrieve messages for.
        :return: None
        """
        self.__reset_message_processing_state()
        for message in self.connector.receive_all_messages(topic=topic):
            self.__process_message(message)
        self.__handle_processed_messages()
        self.__emit_responses()

    def __emit_responses(self):
        """
        Emit all of the necessary messages based on the messages and errors that resulted from
        processing the PubSub's contents.
        :return: None
        """
        pass

    def __handle_processed_messages(self):
        """
        Perform any final housekeeping once all of the messages in the queue have been processed.
        :return: None
        """
        from tasknode.tasks import handle_scanning_order_from_pubsub
        logger.debug(
            "Now handling all processed messages (%s keys in targets)."
            % (len(self._targets),)
        )
        for k, v in self._targets.iteritems():
            if len(v) > 0:
                targets = list(set(v))
                task_sig = handle_scanning_order_from_pubsub.si(
                    org_uuid=k,
                    targets=targets,
                )
                task_sig.options["queue"] = config.celery_priority_queue_name
                self._tasks.append(task_sig)
                self._messages.append(
                    "Total of %s targets defined for organization %s."
                    % (len(targets), k)
                )
        logger.debug(
            "Total number of tasks to kick off is %s."
            % (len(self._tasks),)
        )
        if len(self._tasks) > 0:
            canvas_sig = group(self._task_sigs)
            canvas_sig.apply_async()
        logger.debug("Tasks kicked off.")

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
        if "org_uuid" not in message:
            self._errors.append("org_uuid was not found in message %s." % message)
            return
        org_uuid = message["org_uuid"]
        if not RegexLib.uuid4_string_regex.match(org_uuid):
            self._errors.append("%s was not a valid organization UUID." % org_uuid)
        if "targets" not in message:
            self._errors.append("No targets were found in message %s." % message)
        targets = message["targets"]
        if org_uuid not in self._targets:
            self._targets[org_uuid] = []
        if isinstance(targets, list):
            self._targets[org_uuid].extend(targets)
        else:
            self._targets[org_uuid].append(targets)
        logger.debug(
            "Processed scan message %s."
            % (message,)
        )

    def __reset_message_processing_state(self):
        """
        Reset the internal state of this object to get it ready for processing all of the
        messages found in the PubSub.
        :return: None
        """
        self._errors = []
        self._targets = {}
        self._tasks = []
        self._messages = []

    @property
    def connector(self):
        """
        Get the pubsub connector to use to communicate with the configured PubSub.
        :return: the pubsub connector to use to communicate with the configured PubSub.
        """
        if self._connector is None:
            self._connector = get_pubsub_connector()
        return self._connector
