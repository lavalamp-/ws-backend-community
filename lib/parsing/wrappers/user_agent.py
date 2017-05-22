# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseWrapper
from ...config import ConfigManager

config = ConfigManager.instance()


class UserAgentCsvFileWrapper(BaseWrapper):
    """
    This is a wrapper class that wraps the contents of the Web Sight user agents CSV file.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args):
        self._user_agents = None
        super(UserAgentCsvFileWrapper, self).__init__(*args)

    # Static Methods

    # Class Methods

    @classmethod
    def from_default_file(cls):
        """
        Get an instance of this wrapper class wrapping the contents of the default user agents CSV
        file.
        :return: An instance of this wrapper class wrapping the contents of the default user agents CSV
        file.
        """
        return cls.from_file(config.files_user_agents_path)

    # Public Methods

    # Protected Methods

    def _process_data(self):
        content = [x.strip() for x in self.wrapped_data.strip().split("\n")]
        self._user_agents = [UserAgentCsvLineWrapper(x) for x in content]

    # Private Methods

    # Properties

    @property
    def user_agents(self):
        """
        Get a list of UserAgentCsvLineWrapper objects representing the contents of the wrapped file.
        :return: a list of UserAgentCsvLineWrapper objects representing the contents of the wrapped file.
        """
        return self._user_agents

    @property
    def wrapped_type(self):
        return "User Agents CSV FIle"

    # Representation and Comparison


class UserAgentCsvLineWrapper(BaseWrapper):
    """
    This is a wrapper class that wraps the contents of a single line within the Web Sight user agents
    file.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args):
        self._agent_type = None
        self._agent_name = None
        self._agent_version = None
        self._user_agent = None
        super(UserAgentCsvLineWrapper, self).__init__(*args)

    # Static Methods

    # Class Methods

    # Public Methods

    # Protected Methods

    def _process_data(self):
        to_process = self.wrapped_data
        self._agent_name = to_process[:to_process.find(",")].strip()
        to_process = to_process[to_process.find(",") + 1:]
        self._agent_type = to_process[:to_process.find(",")].strip()
        to_process = to_process[to_process.find(",") + 1:]
        self._agent_version = to_process[:to_process.find(",")].strip()
        to_process = to_process[to_process.find(",") + 1:]
        self._user_agent = to_process.strip()

    # Private Methods

    # Properties

    @property
    def agent_name(self):
        """
        Get the name of the agent referneced by the wrapped line.
        :return: the name of the agent referneced by the wrapped line.
        """
        return self._agent_name

    @property
    def agent_type(self):
        """
        Get the type of agent that the line is in reference to.
        :return: the type of agent that the line is in reference to.
        """
        return self._agent_type

    @property
    def agent_version(self):
        """
        Get the version of the agent that the line is in reference to.
        :return: the version of the agent that the line is in reference to.
        """
        return self._agent_version

    @property
    def user_agent(self):
        """
        Get the user agent string for the line that this wrapper is in reference to.
        :return: the user agent string for the line that this wrapper is in reference to.
        """
        return self._user_agent

    @property
    def wrapped_type(self):
        return "User Agents CSV file line"

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s, %s \"%s\">" % (
            self.__class__.__name__,
            self.agent_type,
            self.agent_name,
            self.user_agent,
        )
