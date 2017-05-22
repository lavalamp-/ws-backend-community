# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .base import BaseElasticsearchModel
from .types import *
from .mixin import IpAddressMixin


class LoginAttemptModel(BaseElasticsearchModel, IpAddressMixin):
    """
    An Elasticsearch model created with every login attempt to Websight.io
    """

    # Class Members
    attempt_date = DateElasticsearchType()
    user_agent = TextElasticsearchType()


    # Instantiation
    def __init__(
            self,
            ip_address=None,
            user_agent=None,
            attempt_date=None,
    ):
        super(LoginAttemptModel, self).__init__()
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.attempt_date = attempt_date


    # Static Methods
    @classmethod
    def create_dummy(cls):
        from lib import WsFaker
        start_time = WsFaker.get_past_time(minutes=20)
        return LoginAttemptModel(
            ip_address=WsFaker.get_ipv4_address(),
            user_agent=WsFaker.get_user_agent(),
            attempt_date=start_time,
        )

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison

    def __repr__(self):
        return "<%s - %s (%s)>" \
               % (
                   self.__class__.__name__,
                   self.ip_address,
                   self.attempt_date,
               )

