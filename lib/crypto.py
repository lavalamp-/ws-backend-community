# -*- coding: utf-8 -*-
import hashlib
import logging
import binascii
import os
import math

logger = logging.getLogger(__name__)


class RandomHelper(object):
    """
    This class contains static methods for generating cryptographically random data.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def flip_coin():
        """
        "Flip a coin" and return a random boolean.
        :return: True or False.
        """
        return bool(ord(os.urandom(1)) % 2)

    @staticmethod
    def get_cryptographic_uuid():
        """
        Get a string containing a UUID that is cryptographically random.
        :return: A string containing a UUID that is cryptographically random.
        """
        random_string = RandomHelper.get_random_token_of_length(32)
        return "%s-%s-%s-%s-%s" % (
            random_string[:8],
            random_string[8:12],
            random_string[12:16],
            random_string[16:20],
            random_string[20:],
        )

    @staticmethod
    def get_entropy_of_string(to_process):
        """
        Calculate the entropy of the string passed in in to_process.
        Taken from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
        :param to_process: The string to process.
        :return: The entropy of the given string.
        """
        entropy = 0
        for i in range(256):
            p_x = float(to_process.count(chr(i))) / len(to_process)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    @staticmethod
    def get_random_token_of_length(length):
        """
        Create a cryptographically random token of the specified length.
        :param length: The length of the token to create.
        :return: A cryptographically random token of the specified length.
        """
        if length % 2 != 0:
            logger.warning(
                "Got an uneven length (%s) in RandomHelper.get_random_token_of_length. While this is fine, "
                "it's recommended to use even numbers."
            )
            urandom_length = length / 2 + 1
        else:
            urandom_length = length / 2
        return binascii.hexlify(os.urandom(urandom_length))[:length]

    @staticmethod
    def roll_dice(sides_count):
        """
        "Roll a dice" and return the number rolled.
        :param sides_count: The number of sides on the dice. Note that this must be <256.
        :return: The number rolled (zero based).
        """
        if sides_count >= 256:
            raise ValueError(
                "Cannot roll a dice with more than 255 sides. Got %s sides."
                % (sides_count,)
            )
        return ord(os.urandom(1)) % sides_count

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison


class HashHelper(object):
    """
    This class contains static methods for generating hex digest hashes of input values.
    """

    # Class Members

    # Instantiation

    # Static Methods

    @staticmethod
    def md5_digest(content):
        """
        Get the MD5 hex digest of the contents specified via argument.
        :param content: The contents to get an MD5 hex digest for.
        :return: The MD5 hex digest of contents.
        """
        m = hashlib.md5()
        m.update(content)
        return m.hexdigest()

    @staticmethod
    def sha256_digest(content):
        """
        Get the SHA256 hex digest of the content specified via argument.
        :param content: The contents to get a SHA256 hex digest for.
        :return: A SHA256 hex digest representing the data in content.
        """
        s = hashlib.sha256()
        s.update(content)
        return s.hexdigest()

    # Class Methods

    # Public Methods

    # Protected Methods

    # Private Methods

    # Properties

    # Representation and Comparison
