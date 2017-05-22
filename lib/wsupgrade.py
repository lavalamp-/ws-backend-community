# -*- coding: utf-8 -*-
from __future__ import absolute_import

from elasticsearch import TransportError

import logging
from .config import ConfigManager
from .filesystem import FilesystemHelper

logger = logging.getLogger(__name__)
config = ConfigManager.instance()


class UpgradeHelper(object):
    """
    This class contains helper methods for managing upgrades as the production Web Sight deployment
    is updated to reflect new functionality.
    """

    # Class Members

    # Instantiation

    def __init__(self):
        self._db_session = None

    # Static Methods

    # Class Methods

    # Public Methods

    def add_admin_groups_to_organizations(self):
        """
        Update all of the organizations in the database to ensure that they all have administrative
        groups associated with them.
        :return: None
        """
        from .sqlalchemy import Organization, WsAuthGroup
        organizations = self.db_session.query(Organization).all()
        for organization in organizations:
            logger.warning(
                "Now processing auth groups for organization %s."
                % (organization.name,)
            )
            write_group = filter(lambda x: x.name == "org_write", organization.auth_groups)
            if not write_group:
                logger.error(
                    "Organization %s does not have a write group. Skipping."
                    % (organization.name,)
                )
                continue
            write_group = write_group[0]
            if len(write_group.users) == 0:
                logger.error(
                    "Write group for organization %s has no members. Skipping."
                    % (organization.name,)
                )
                continue
            admin_user = write_group.users[0]
            admin_group = filter(lambda x: x.name == "org_admin", organization.auth_groups)
            if len(admin_group) > 0:
                logger.error(
                    "Organization %s already has an admin group. Skipping."
                    % (organization.name,)
                )
                continue
            new_group = WsAuthGroup.new(
                name="org_admin",
                organization_id=organization.uuid,
            )
            new_group.users.append(admin_user)
            self.db_session.add(new_group)
        logger.warning(
            "Now committing new auth groups (%s of them) to database."
            % (len(self.db_session.new),)
        )
        self.db_session.commit()

    def add_scan_ports_to_organizations(self):
        """
        Add all of the default scan ports to all of the organizations currently in the database.
        :return: None
        """
        from .sqlalchemy import ScanPort, Organization, get_ports_to_scan_for_organization
        organizations = self.db_session.query(Organization).all()
        default_scan_ports = self.__get_default_scan_ports()
        for org in organizations:
            org_scan_ports = get_ports_to_scan_for_organization(org_uuid=org.uuid, db_session=self.db_session)
            for scan_port in default_scan_ports:
                if scan_port in org_scan_ports:
                    logger.warning(
                        "Scan port of %s is already included in scan ports for organization %s."
                        % (scan_port, org.uuid)
                    )
                else:
                    new_port = ScanPort.new(
                        port_number=scan_port[0],
                        protocol=scan_port[1],
                        organization_id=org.uuid,
                    )
                    self.db_session.add(new_port)
        logger.warning("Now committing all new scan ports to database.")
        self.db_session.commit()
        logger.warning("Scan ports committed successfully.")

    def close_session(self):
        """
        Close the database session associated with this object.
        :return: None
        """
        if self._db_session is not None:
            self._db_session.close()

    def update_all_es_model_mappings(self):
        """
        Update all of the Elasticsearch model mappings that are currently deployed in the configured
        deployment.
        :return: None
        """
        from .sqlalchemy import get_all_organization_uuids
        from wselasticsearch import bootstrap_index_model_mappings
        org_uuids = get_all_organization_uuids(self.db_session)
        logger.warning(
            "Now updating ES model mappings for %s organizations."
            % (len(org_uuids),)
        )
        for org_uuid in org_uuids:
            logger.warning(
                "Updating ES model mappings for organization %s."
                % (org_uuid,)
            )
            try:
                bootstrap_index_model_mappings(index=org_uuid, delete_first=False)
            except TransportError as e:
                logger.error(
                    "Error thrown when attempting to set mappings for index %s: %s"
                    % (org_uuid, e.message)
                )
        logger.warning(
            "Updated all ES model mappings for all organizations in the configured database."
        )

    # Protected Methods

    # Private Methods

    def __get_default_scan_ports(self):
        """
        Get a list of tuples depicting the default scanning ports that should be associated with
        all organizations.
        :return: A list of tuples depicting the default scanning ports that should be associated with
        all organizations.
        """
        contents = FilesystemHelper.get_file_contents(path=config.files_default_scan_ports_path)
        to_return = []
        contents = [x.strip() for x in contents.strip().split("\n")]
        for line in contents:
            line_split = [x.strip() for x in line.split(",")]
            to_return.append((int(line_split[0]), line_split[1]))
        return to_return

    # Properties

    @property
    def db_session(self):
        """
        Get a SQLAlchemy session to use to query the configured database.
        :return: a SQLAlchemy session to use to query the configured database.
        """
        if self._db_session is None:
            from .sqlalchemy import get_sa_session
            self._db_session = get_sa_session()
        return self._db_session

    # Representation and Comparison

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)

