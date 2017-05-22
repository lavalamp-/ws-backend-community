# -*- coding: utf-8 -*-
from __future__ import absolute_import

from .singleton import Singleton

from lib import ConfigManager
import logging

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


@Singleton
class FingerprintHelper(object):
    """
    This is a helper class for managing fingerprints used by the Web Sight platform.
    """

    # Class Members

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def add_all_fingerprints_to_db(self):
        """
        Process the contents of the Web Sight fingerprints file and ensure that every fingerprint
        in the file is persisted to the Web Sight database.
        :return: None
        """
        from lib.sqlalchemy import does_hash_fingerprint_exist, get_sa_session, HashFingerprint
        session = get_sa_session()
        for sha256, description, version, es_attr in self.__iter_file_fingerprints():
            if does_hash_fingerprint_exist(db_session=session, sha256_hash=sha256):
                logger.debug(
                    "SHA256 hash of %s already exists in database. Skipping."
                    % (sha256,)
                )
            else:
                logger.debug(
                    "Now adding SHA256 hash of %s (%s) to database."
                    % (sha256, description)
                )
                new_fingerprint = HashFingerprint.new(
                    hash=sha256,
                    version=version,
                    title=description,
                    es_attribute=es_attr,
                )
                session.add(new_fingerprint)
        logger.debug(
            "Now committing a total of %s new fingerprints to the database."
            % (len(session.new),)
        )
        session.commit()
        logger.debug("Fingerprints added succesfully.")
        session.close()

    # Protected Methods

    # Private Methods

    def __iter_file_fingerprints(self):
        """
        Get a generator that, when iterated over, returns tuples that contain (1) the SHA256 hash of
        the fingerprint, (2) a brief description of the fingerprinted technology, (3) the version that
        the hash is from and (4) a string representing the attribute that will be applied to Elasticsearch
        models that match the fingerprint.
        :return: A generator that, when iterated over, returns tuples that contain (1) the SHA256 hash of
        the fingerprint, (2) a brief description of the fingerprinted technology, (3) the version that
        the hash is from and (4) a string representing the attribute that will be applied to Elasticsearch
        models that match the fingerprint.
        """
        with open(config.files_fingerprints_path, "r") as f:
            for line in f:
                to_return = [x.strip() for x in line.strip().split(",")]
                yield to_return

    # Properties

    # Representation and Comparison
