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

    def publish_elasticsearch_document(self, es_doc, topic=config.pubsub_publish_topic):
        """
        Send a message to the given topic containing the contents of the given Elasticsearch
        document.
        :param es_doc: The Elasticsearch document to send.
        :param topic: The topic to publish the document to.
        :return: None
        """
        self.__emit(
            topic=topic,
            message_type="data",
            message_content={
                "data_type": es_doc.get_doc_type(),
                "data": es_doc.to_es_dict(),
            }
        )

    def send_scan_error_message(self, error_message):
        """
        Send an error message to the default outbound topic describing an error that was encountered
        when trying to kick off a scan.
        :param error_message: The message to emit.
        :return: None
        """
        self.__emit_error(error_message)

    def send_scan_success_message(
            self,
            org_uuid=None,
            order_uuid=None,
            skipped_targets=None,
            too_soon_targets=None,
            domains=None,
            networks=None,
    ):
        """
        Send a message to the default outbound topic describing the successful status of the order
        that was kicked off.
        :param org_uuid: The UUID of the organization that the scan was kicked off for.
        :param order_uuid: The UUID of the order that the scan is under.
        :param skipped_targets: A list of targets that were skipped.
        :param too_soon_targets: A list of targets that had been scanned too recently.
        :param domains: A list of the domains in the scan.
        :param networks: A list of networks in the scan.
        :return: None
        """
        to_send = {
            "message": "A scan was successfully started for the organization %s (order UUID is %s). The scan will "
                       "target %s domain names and %s networks." % (org_uuid, order_uuid, len(domains), len(networks)),
            "skipped": skipped_targets,
            "too-soon": too_soon_targets,
            "domains": domains,
            "networks": networks,
        }
        self.__emit_message(to_send)

    def __emit(self, topic=config.pubsub_publish_topic, message_type=None, message_content=None):
        """
        Emit the given message to the given topic.
        :param topic: The topic to emit the message to.
        :param message_type: The type of message to emit.
        :param message_content: The content of the message.
        :return: None
        """
        self.connector.publish_message(
            topic=topic,
            message={
                "broadcast_type": message_type,
                "content": message_content,
            }
        )

    def __emit_error(self, to_emit):
        """
        Emit the given text as an error to the PubSub.
        :param to_emit: The error text to emit.
        :return: None
        """
        self.__emit(message_type="error", message_content=to_emit)

    def __emit_message(self, to_emit):
        """
        Emit the given text as a message to the PubSub.
        :param to_emit: The message text to emit.
        :return: None
        """
        self.__emit(message_type="message", message_content=to_emit)

    def __emit_responses(self):
        """
        Emit all of the necessary messages based on the messages and errors that resulted from
        processing the PubSub's contents.
        :return: None
        """
        logger.debug(
            "Now emitting all responses (%s messages, %s errors)."
            % (len(self._messages), len(self._errors))
        )
        for error in self._errors:
            self.__emit_error(error)
        for message in self._messages:
            self.__emit_message(message)
        logger.debug("All responses successfully emitted.")

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
            canvas_sig = group(self._tasks)
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
        Process the contents of the given message as a scan message. A scan message should
        look as follows:

        {
            "message_type": "scan",
            "targets": [
                "8.8.8.8",
                "8.8.8.8/24",
                "www.foo.com",
            ],
            "org_uuid": "4c66e779-cad8-4867-b64a-baec8a792447",
        }

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
