# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchQuery
import logging
from elasticsearch import JSONSerializer

from .exception import BulkOperationNotSupportedError, EmptyBulkQueueError
from lib import ValidationHelper, ConfigManager

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


class BulkElasticsearchQuery(BaseElasticsearchQuery):
    """
    This class handles running bulk operations against an Elasticsearch endpoint.
    """

    # Class Members

    # Instantiation

    def __init__(self):
        super(BulkElasticsearchQuery, self).__init__()
        self._batch_queue = []
        self._current_batch_operations = None
        self._current_batch_size = None
        self._serializer = None

    # Static Methods

    # Class Methods

    # Public Methods

    def add_model_for_indexing(self, model=None, index=None):
        """
        Add the given model to the batch queue to be indexed.
        :param model: The model to add to the batch queue.
        :param index: The index the model should be indexed within.
        :return: None
        """
        ValidationHelper.validate_es_model_type(model)
        self._batch_queue.append(("index", index, model))

    def add_models_for_indexing(self, models=None, index=None):
        """
        Add the given models to the batch queue to be indexed.
        :param models: A list of models to add to the batch queue.
        :param index: The index the models should be indexed within.
        :return: None
        """
        for model in models:
            self.add_model_for_indexing(model=model, index=index)

    def save(self):
        """
        Process the current contents of the batch_queue in bulk updates to the Elasticsearch
        endpoint.
        :return: None
        """
        if len(self.batch_queue) == 0:
            raise EmptyBulkQueueError(
                "Attempted to perform bulk update when no operations were queued."
            )
        self._current_batch_operations = []
        self._current_batch_size = 0
        logger.debug(
            "Now performing bulk updates for a total of %s operations."
            % (len(self.batch_queue),)
        )
        while True:
            operation, index, model = self._batch_queue.pop(0)
            if operation == "index":
                self.__add_model_to_batch_for_indexing(index=index, model=model)
            else:
                raise BulkOperationNotSupportedError("No support for operation %s." % (operation,))
            if self._current_batch_size >= config.es_bulk_update_max_size:
                logger.debug(
                    "Maximum bulk update size exceeded. Sending %s bulk operations now."
                    % (len(self._current_batch_operations),)
                )
                self.__send_batch()
            if len(self._batch_queue) == 0:
                break
        if len(self._current_batch_operations) > 0:
            logger.debug(
                "Sending final batch of operations of length %s."
                % (len(self._current_batch_operations),)
            )
            self.__send_batch()
        self._current_batch_operations = self._current_batch_size = None
        logger.debug("Bulk operations performed successfully.")

    # Protected Methods

    # Private Methods

    def __add_model_to_batch_for_indexing(self, index=None, model=None):
        """
        Add the given model to be indexed in the current batch body.
        :param index: The index where the model should be indexed within.
        :param model: The model to index.
        :return: None
        """
        index_meta = {
            "index": {
                "_index": index,
                "_type": model.doc_type,
            }
        }
        index_meta_string = self.serializer.dumps(index_meta)
        self._current_batch_operations.append(index_meta_string)
        self._current_batch_size += len(index_meta_string) + 1
        model_string = self.serializer.dumps(model.to_es_dict())
        self._current_batch_operations.append(model_string)
        self._current_batch_size += len(model_string)

    def __send_batch(self, clear_batch=True):
        """
        Send the current contents of self._current_batch_operations to the Elasticsearch endpoint.
        :param clear_batch: Whether or not to reset the current internal state of this object to
        reflect that the batch has been successfully processed.
        :return: The response from the Elasticsearch endpoint.
        """
        request_body = "\n".join(self._current_batch_operations)
        if not isinstance(request_body, unicode):
            request_body = request_body.decode("utf-8")
        to_return = self.es_helper.bulk_request(body=request_body)
        if clear_batch:
            self._current_batch_operations = []
            self._current_batch_size = 0
        return to_return

    # Properties

    @property
    def batch_length(self):
        """
        Get the length of the current batch_queue.
        :return: the length of the current batch_queue.
        """
        return len(self.batch_queue)

    @property
    def batch_queue(self):
        """
        Get the queue of batch events that are currently queued up for processing.
        :return: the queue of batch events that are currently queued up for processing.
        """
        return self._batch_queue

    @property
    def serializer(self):
        """
        Get the serializer to use to serialize batch operation contents.
        :return: the serializer to use to serialize batch operation contents.
        """
        if self._serializer is None:
            self._serializer = JSONSerializer()
        return self._serializer

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s operations in queue>" % (self.__class__.__name__, len(self.batch_queue))

