# -*- coding: utf-8 -*-
from __future__ import absolute_import
import redis
from .config import ConfigManager
from .singleton import Singleton
import logging

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


@Singleton
class RedisHelper(object):
    """
    A class containing helper methods for accessing Redis functionality in Singleton fashion.
    """

    # Class Members

    _pubsub = None
    _redis = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def decrement_tags(self, tags):
        """
        Decrement all of the counters associated with the specified tags in the Redis
        back-end in one atomic operation.
        :param tags: A list of strings representing the tag keys to decrement.
        :return: An array of integers depicting the counter values after decrementing them.
        """
        pl = self.redis.pipeline()
        for tag in tags:
            pl.decr(tag)
        return pl.execute()

    def delete(self, key):
        """
        Delete the given key from Redis.
        :param key: The key to delete.
        :return: A number depicting how many records were deleted.
        """
        return self.redis.delete(key)

    def get(self, key):
        """
        Get the value associated with the given key in Redis.
        :param key: The key to retrieve.
        :return: The value associated with the given key in redis.
        """
        return self.redis.get(key)

    def get_tag(self, tag):
        """
        Get the value in Redis associated with the specified tag.
        :param tag: The tag to retrieve the value for.
        :return: The value associated with the given tag.
        """
        return self.redis.get(tag)

    def increment_tags(self, tags):
        """
        Increment all of the counters associated with the specified tags in the Redis
        back-end in one atomic operation.
        :param tags: A list of strings representing the tag keys to increment.
        :return: An array of integers depicting the counter values after incrementing them.
        """
        pl = self.redis.pipeline()
        for tag in tags:
            pl = pl.incr(tag)
        return pl.execute()

    def set(self, key=None, value=None, ttl=None):
        """
        Set the given key to the given value in Redis.
        :param key: The key to set.
        :param value: The value to set the key to.
        :param ttl: The amount of time in seconds that this value should remain set in Redis.
        :return: A boolean depicting whether or not the value was set correctly.
        """
        to_return = self.redis.set(key, value)
        if to_return and ttl:
            self.redis.expire(key, ttl)
        return to_return

    # Protected Methods

    # Private Methods

    # Properties

    @property
    def pubsub(self):
        """
        Get the Redis PubCub associated with the configured Redis server.
        :return: The Redis PubCub associated with the configured Redis server.
        """
        if self._pubsub is None:
            self._pubsub = self.redis.pubsub(ignore_subscribe_messages=True)
        return self._pubsub

    @property
    def redis(self):
        """
        Get the Redis connector configured in the DataHound configuration file.
        :return: The Redis connector configured in the DataHound configuration file.
        """
        if self._redis is None:
            self._redis = redis.Redis(
                host=config.redis_host,
                port=config.redis_port,
            )
        return self._redis

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s>" % (self.__class__.__name__, self.redis)
