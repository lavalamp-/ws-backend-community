# -*- coding: utf-8 -*-
from __future__ import absolute_import

import importlib
import inspect


def get_import_path_for_type(import_type):
    """
    Get a string representing the import path for the given object.
    :param import_type: The object to get the import path for.
    :return: A string representing the import path for the given object.
    """
    if inspect.isclass(import_type):
        return "%s.%s" % (import_type.__module__, import_type.__name__)
    else:
        return "%s.%s" % (import_type.__module__, import_type.__class__.__name__)


def get_class_from_import_string(import_string):
    """
    Get the class that is pointed to by the given string.
    :param import_string: A dot-delimited string depicting where the class to return resides.
    :return: The class pointed to by import_string.
    """
    import_path = import_string[:import_string.rfind(".")]
    class_name = import_string[import_string.rfind(".") + 1:]
    module = importlib.import_module(import_path)
    return getattr(module, class_name)
