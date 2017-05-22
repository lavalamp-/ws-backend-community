# -*- coding: utf-8 -*-
from __future__ import absolute_import

from lib import DictableMixin, ConfigManager, DatetimeHelper
from .exception import NoKeyAvailableError

config = ConfigManager.instance()


class BaseElasticsearchScript(DictableMixin):
    """
    A base class for Elasticsearch update classes.
    """

    # Class Members

    # Instantiation

    def __init__(self, script_language=config.es_scripting_language, script_type="inline"):
        self._script_language = script_language
        self._script_lines = []
        self._script_type = script_type

    # Static Methods

    # Class Methods

    # Public Methods

    def add_script_line(self, line):
        """
        Add the given line as a line of the script to execute.
        :param line: The line to execute.
        :return: None
        """
        self._script_lines.append(line)

    # Protected Methods

    def _get_script_body(self):
        """
        Get a dictionary representing the script body that this update is configured to use.
        :return: A dictionary representing the script body that this update is configured to use.
        """
        return {
            "lang": self.script_language,
            self.script_type: self.script_body,
        }

    # Private Methods

    # Properties

    @property
    def context(self):
        """
        Get a string representing the context that this update script operates upon.
        :return: a string representing the context that this update script operates upon.
        """
        return "ctx.%s" % (self.context_type,)

    @property
    def context_type(self):
        """
        Get the context type that this update script uses.
        :return: the context type that this update script uses.
        """
        raise NotImplementedError("Subclasses must implement this!")

    @property
    def key(self):
        return self.name

    @property
    def name(self):
        """
        Get the basic update name.
        :return: the basic update name.
        """
        return "script"

    @property
    def script_body(self):
        """
        Get the body of the script that will be run with this update.
        :return: the body of the script that will be run with this update.
        """
        return "; ".join(self.script_lines)

    @property
    def script_language(self):
        """
        Get the language that Elasticsearch should use to run the update script.
        :return: the language that Elasticsearch should use to run the update script.
        """
        return self._script_language

    @property
    def script_lines(self):
        """
        Get a list of strings of scripting code for this script.
        :return: a list of strings of scripting code for this script.
        """
        return self._script_lines

    @property
    def script_type(self):
        """
        Get the script type that this update uses.
        :return: the script type that this update uses.
        """
        return self._script_type

    @property
    def value(self):
        """
        Get the value that should be used for the update.
        :return: the value that should be used for the update.
        """
        return self._get_script_body()

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)


class BaseSourceElasticsearchScript(BaseElasticsearchScript):
    """
    This is a base class for scripted updates that modify the _source of Elasticsearch documents
    """

    # Class Members

    # Instantiation

    def __init__(self, **kwargs):
        super(BaseSourceElasticsearchScript, self).__init__(**kwargs)
        self._params = {}

    # Static Methods

    # Class Methods

    # Public Methods

    def add_equals(self, key=None, value=None):
        """
        Add a scripting line to this script that sets the given key of the related model to
        the given value.
        :param key: The key to set the value to.
        :param value: The value to set it to.
        :return: None
        """
        params_key = self.__get_unused_key(key)
        script_line = "%s.%s = params.%s" % (self.context, key, params_key)
        self.add_script_line(script_line)
        self.__add_parameter(key=params_key, value=value)

    def add_equals_now(self, key):
        """
        Add a scripting line to this script that sets the given key of the referenced model to
        the current datetime.
        :param key: The key to update.
        :return: None
        """
        self.add_equals(key=key, value=DatetimeHelper.now())

    def add_increment(self, key):
        """
        Add a scripting line to this script that increments the given key of the related model.
        :param key: The key to increment.
        :return: None
        """
        script_line = "%s.%s++" % (self.context, key)
        self.add_script_line(script_line)

    # Protected Methods

    def _get_script_body(self):
        to_return = super(BaseSourceElasticsearchScript, self)._get_script_body()
        if len(self.params) > 0:
            to_return["params"] = self.params
        return to_return

    # Private Methods

    def __add_parameter(self, key=None, value=None):
        """
        Add the given parameter to the list of parameters in this script.
        :param key: The key to add.
        :param value: The value to add.
        :return: None
        """
        self._params[key] = value

    def __get_unused_key(self, key):
        """
        Get a string representing a key that is not yet being used in the script's parameters.
        :param key: The key to process.
        :return: A string representing a key that is not yet being used in the script's parameters.
        """
        if key not in self.params:
            return key
        for i in range(100):
            new_key = "%s%s" % (key, i)
            if new_key not in self.params:
                return new_key
        raise NoKeyAvailableError(
            "No usable key found for base key of %s. Parameters were %s."
            % (key, self.params)
        )

    # Properties

    @property
    def context_type(self):
        return "_source"

    @property
    def params(self):
        """
        Get a dictionary of the parameters that are configured in this scripted update.
        :return: a dictionary of the parameters that are configured in this scripted update.
        """
        return self._params

    # Representation and Comparison
