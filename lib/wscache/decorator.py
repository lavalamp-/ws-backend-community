# -*- coding: utf-8 -*-
from __future__ import absolute_import

from functools import wraps
from datetime import datetime
import inspect
import json

from ..validation import ValidationHelper
from ..exception import BaseWsException
from ..crypto import HashHelper
from .util import get_import_path_for_type
from ..wsredis import RedisHelper
from .serializer import WsSerializableJSONEncoder


class UncacheableError(BaseWsException):
    """
    This is an error for denoting that a value cannot be used to generate a cache key.
    """

    _message = "Not a cacheable value."


def double_wrap(f):
    """
    a decorator decorator, allowing the decorator to be used as:
    @decorator(with, arguments, and=kwargs)
    or
    @decorator

    http://stackoverflow.com/questions/653368/how-to-create-a-python-decorator-that-can-be-used-either-with-or-without-paramet
    """
    @wraps(f)
    def new_dec(*args, **kwargs):
        if len(args) == 1 and len(kwargs) == 0 and callable(args[0]):
            return f(args[0])
        else:
            return lambda realf: f(realf, *args, **kwargs)

    return new_dec


def get_cache_key_from_function_call(f, args, kwargs):
    """
    Get the key to use for the Redis cache for storing the results of the given function call.
    :param f: The function that is wrapped by the cache call.
    :param args: Positional arguments passed to the function.
    :param kwargs: Keyword arguments passed to the function.
    :return: A string representing the cache key that should be used to retrieve and store data returned
    by the wrapped function.
    """
    if is_method_defined_in_class(f):
        key_arguments = [args[1:], kwargs]
        function_name = "%s.%s" % (get_import_path_for_type(args[0]), f.func_name)
    else:
        key_arguments = [args, kwargs]
        function_name = f.func_name
    func_arguments_cache_key = get_cache_key_argument_from_value(key_arguments)
    return "%s-%s" % (function_name, func_arguments_cache_key)


def get_cache_key_argument_from_value(to_cache):
    """
    Get a string describing the contents of to_cache as part of the key generated for caching function call
    results.
    :param to_cache: The value to cache.
    :return: A string describing the contents of to_cache to be used as part of the cache key generation.
    """
    ValidationHelper.validate_cacheable_type(to_cache)
    if isinstance(to_cache, str):
        return string_to_cache_key_component("str-%s" % to_cache)
    elif isinstance(to_cache, unicode):
        return string_to_cache_key_component("unicode-%s" % to_cache)
    elif isinstance(to_cache, bool):
        return string_to_cache_key_component("bool-%s" % to_cache)
    elif isinstance(to_cache, list):
        to_process = []
        for value in sorted(to_cache):
            to_process.append(get_cache_key_argument_from_value(value))
        return string_to_cache_key_component("list-%s" % ",".join(to_process))
    elif isinstance(to_cache, dict):
        to_process = []
        for key in sorted(to_cache):
            to_process.append("%s-%s" % (key, get_cache_key_argument_from_value(to_cache[key])))
        return string_to_cache_key_component("dict-%s" % ",".join(to_process))
    elif isinstance(to_cache, int):
        return string_to_cache_key_component("int-%s" % to_cache)
    elif isinstance(to_cache, datetime):
        epoch = datetime(1970, 1, 1)
        total_seconds = (to_cache - epoch).total_seconds()
        return string_to_cache_key_component("datetime-%s" % total_seconds)
    elif isinstance(to_cache, tuple):
        to_process = [get_cache_key_argument_from_value(x) for x in to_cache]
        return string_to_cache_key_component("tuple-%s" % ",".join(to_process))
    else:
        raise UncacheableError(
            "Value of %s (%s) is not cacheable."
            % (to_cache, type(to_cache))
        )


def string_to_cache_key_component(key_string):
    """
    Convert the contents of the given string into a component used in the generation of a Redis cache key.
    :param key_string: The string to parse.
    :return: A string representing the contents of key_string to be used as a component in a Redis cache key.
    """
    return HashHelper.md5_digest(key_string)


def is_method_defined_in_class(f):
    """
    Check to see if the given function is a method that's defined in a class.
    :param f: The function to check.
    :return: True if the given function is a method defined in a class, False otherwise.
    """
    args = inspect.getargspec(f).args
    return bool(args and args[0] == "self")


@double_wrap
def redis_cache(f, cache_ttl=3600):
    """
    This is a decorator that caches the return value of the wrapped function in Redis. Note that if the
    return value of the wrapped function is not one of the fields supported by the Python JSON encoder, then
    WsSerializableJSONEncoder must be updated to support serialization and deserialization of the given object
    type.
    :param f: The function being wrapped.
    :param cache_ttl: The amount of time in seconds that data returned from the wrapped function should
    be cached in Redis.
    :return: The wrapped function.
    """

    @wraps(f)
    def cache_wrapper(*args, **kwargs):
        cache_key = get_cache_key_from_function_call(f, args, kwargs)
        redis_helper = RedisHelper.instance()
        cached_value = redis_helper.get(cache_key)
        serializer = WsSerializableJSONEncoder()
        if cached_value:
            cached_value = json.loads(cached_value)
            return serializer.decode(cached_value)
        else:
            to_return = f(*args, **kwargs)
            cache_data = serializer.encode(to_return)
            cache_data = json.dumps(cache_data)
            redis_helper.set(key=cache_key, value=cache_data, ttl=cache_ttl)
            return to_return

    return cache_wrapper
