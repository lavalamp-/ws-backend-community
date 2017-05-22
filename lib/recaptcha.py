# -*- coding: utf-8 -*-
from __future__ import absolute_import
from lib.config import ConfigManager
import requests

config = ConfigManager.instance()


class RecaptchaHelper(object):
    """
    A helper class for verifying recaptcha responses
    """

    # Class Members

    _verify_url = 'https://www.google.com/recaptcha/api/siteverify'

    # Instantiation

    # Static Methods


    # Class Methods

    @classmethod
    def is_valid_response(cls, response):
        """
        This will query the google recaptcha api, and verify the response
        :param response: the response to verify
        :return: True if it is valid
        """
        secret = config.recaptcha_secret
        data = {
            'secret': secret,
            'response': response
        }
        response = requests.post(cls._verify_url, data=data)
        is_valid = False
        if response.status_code == 200:
            response_json = response.json()
            if 'success' in response_json:
                is_valid = response_json['success']
        return is_valid


    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison