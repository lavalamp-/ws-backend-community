# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging

from django.utils import timezone
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.functions import count
from aldjemy.core import get_engine

from ..base import BaseWebSightTestCase
from ..data import WsTestData
from lib.sqlalchemy import WsUser, Organization, WsAuthGroup, Network, IpAddress, WebServiceScan

logger = logging.getLogger(__name__)
Session = sessionmaker()


class BaseSqlalchemyTestCase(BaseWebSightTestCase):
    """
    This is a base class for test cases that interact with Web Sight data via SQLAlchemy.
    """

    # Class Members

    # Instantiation

    def __init__(self, *args, **kwargs):
        super(BaseSqlalchemyTestCase, self).__init__(*args, **kwargs)
        self._db_session = None
        self._transaction = None
        self._connection = None
        self._to_delete = []

    # Static Methods

    # Class Methods

    # Public Methods

    def count_ip_addresses(self):
        """
        Get the number of IP addresses currently in the database.
        :return: The number of IP addresses currently in the database.
        """
        return self.count_model(IpAddress)

    def count_model(self, model_class):
        """
        Get the total number of instances of the given model class that currently exist in the
        database.
        :param model_class: The SQLAlchemy class to count.
        :return: The total number of instances of the given model class that currently exist in the
        database.
        """
        return self.db_session.query(count(model_class.uuid)).one()[0]

    def count_networks(self):
        """
        Get the number of networks currently in the database.
        :return: The number of networks currently in the database.
        """
        return self.count_model(Network)

    def create_network_for_user(
            self,
            user="user_1",
            organization=None,
            address=WsTestData.UNUSED_IP_ADDRESS,
            name="Awesome Network",
            mask_length=24,
            scanning_enabled=True,
            added_by="user",
    ):
        """
        Create and return a new network for the given user.
        :param user: The user to create the network for.
        :param organization: The organization to associate the network with. If None, defaults to
        the default organization for the user.
        :param address: The address for the network.
        :param name: The name to give the network.
        :param mask_length: The mask length of the network.
        :param scanning_enabled: Whether or not scanning is enabled for the network.
        :param added_by: Who the network was added by.
        :return: The newly-created network.
        """
        if organization is None:
            organization = self.get_organization_for_user(user=user)
        create_kwargs = {
            "address": address,
            "mask_length": mask_length,
            "scanning_enabled": scanning_enabled,
            "endpoint_count": pow(2, 32 - mask_length),
            "cidr_range": "%s/%s" % (address, mask_length),
            "added_by": added_by,
            "times_scanned": 0,
            "last_scan_time": None,
            "name": name,
            "organization_id": organization.uuid,
        }
        return self.__create_model_instance(model_class=Network, create_kwargs=create_kwargs)

    def create_web_service_scan_for_user(
            self,
            user="user_1",
            uuid=WsTestData.WEB_SERVICE_ANALYSIS_UUID,
            web_service=None,
    ):
        """
        Create and return a new web service scan associated with the given web service and owned by
        the given user.
        :param user: The user to create the web service scan for.
        :param uuid: The UUID to associate with the web service scan.
        :param web_service: The web service to add the web service scan to. If this is None, then defaults to
        the default web service associated with the given user.
        :return: The newly-created web service scan.
        """
        if web_service is None:
            web_service = self.get_web_service_for_user(user=user)
        create_kwargs = {
            "started_at": timezone.now(),
            "web_service_id": web_service.uuid,
            "uuid": uuid,
        }
        return self.__create_model_instance(model_class=WebServiceScan, create_kwargs=create_kwargs)

    def get_ip_address_for_user(self, user="user_1"):
        """
        Get an IP address owned by the given user.
        :param user: A string depicting the user to retrieve an IP address for.
        :return: An IP address owned by the given user.
        """
        return self.get_network_for_user(user=user).ip_addresses[0]

    def get_last_created(self, model_class):
        """
        Get the most recently created instance of the given model class.
        :param model_class: The model class to get the most recently-created instance of.
        :return: The most recently created instance of the given model class.
        """
        return self.db_session.query(model_class).order_by(getattr(model_class, "created").desc()).first()

    def get_last_created_network(self):
        """
        Get the most recently created network.
        :return: The most recently created network.
        """
        return self.get_last_created(Network)

    def get_network_for_user(self, user="user_1"):
        """
        Get a network owned by the specified user.
        :param user: The user to retrieve the network for.
        :return: A network owned by the specified user.
        """
        return self.get_organization_for_user(user=user).networks[0]

    def get_network_service_for_user(self, user="user_1"):
        """
        Get a network service owned by the given user.
        :param user: A string depicting the user to retrieve a network service for.
        :return: A network service owned by the given user.
        """
        return self.get_ip_address_for_user(user=user).network_services[0]

    def get_organization_for_user(self, user="user_1"):
        """
        Get an organization owned by the specified user.
        :param user: A string representing the user to get the organization for.
        :return: An organization owned by the specified user.
        """
        user = self.get_user(user=user)
        return self.db_session.query(Organization)\
            .join(WsAuthGroup, WsAuthGroup.organization_id == Organization.uuid)\
            .join((WsUser, WsAuthGroup.users))\
            .filter(WsAuthGroup.name == u"org_admin")\
            .filter(WsUser.uuid == user.uuid)\
            .first()

    def get_user(self, user="user_1"):
        """
        Get the user object corresponding to the given user string.
        :param user: A string depicting the user to retrieve.
        :return: The user object corresponding to the given user string.
        """
        user_data = self.get_user_data(user=user)
        return self.db_session.query(WsUser)\
            .filter(WsUser.username == user_data["username"])\
            .one()

    def get_web_service_for_user(self, user="user_1"):
        """
        Get a web service object owned by the given user.
        :param user: The user to retrieve a web service object for.
        :return: A web service owned by the given user.
        """
        return self.get_network_service_for_user(user=user).web_services[0]

    def get_web_service_scan_for_user(self, user="user_1"):
        """
        Get a web service scan owned by the given user.
        :param user: The user to retrieve the web service scan for.
        :return: A web service scan owned by the given user.
        """
        return self.get_web_service_for_user(user=user).web_service_scans[0]

    def setUp(self):
        """
        Set up this test case by initializing all lazily-loaded variables to None.
        :return: None
        """
        super(BaseSqlalchemyTestCase, self).setUp()
        self._db_session = None
        self._transaction = None
        self._connection = None
        self._to_delete = []

    def tearDown(self):
        """
        Tear down this test case by closing any existing database connection and deleting all of the
        objects that were marked for deletion.
        :return: None
        """
        if len(self.to_delete) > 0:
            for cur_delete in self.to_delete:
                try:
                    self.db_session.delete(cur_delete)
                except InvalidRequestError:
                    continue
            self.db_session.commit()
        if self._db_session is not None:
            self._db_session.close()
        if self._transaction is not None:
            self._transaction.rollback()
        if self._connection is not None:
            self._connection.close()
        super(BaseSqlalchemyTestCase, self).tearDown()

    # Protected Methods

    # Private Methods

    def __add_for_deletion(self, to_delete):
        """
        Add the given model instance to the list of models to delete upon conclusion of each unit test.
        :param to_delete: The model instance to delete.
        :return: None
        """
        self._to_delete.append(to_delete)

    def __create_model_instance(self, model_class=None, create_kwargs=None):
        """
        Create and return an instance of the given model class based on the given kwargs and add the
        model to the list of models to delete.
        :param model_class: The model class to create an instance of.
        :param create_kwargs: Keyword arguments to pass to the creation method.
        :return: The newly-created model instance.
        """
        to_return = model_class.new(**create_kwargs)
        self.db_session.add(to_return)
        return to_return

    # Properties

    @property
    def connection(self):
        """
        Get the database connection to use for testing.
        :return: the database connection to use for testing.
        """
        if self._connection is None:
            self._connection = get_engine().connect()
        return self._connection

    @property
    def db_session(self):
        """
        Get a SQLAlchemy session to use to interact with the Web Sight database.
        :return: a SQLAlchemy session to use to interact with the Web Sight database.
        """
        if self._db_session is None:
            self._transaction = self.connection.begin()
            self._db_session = Session(bind=self.connection)

            original_add = self._db_session.add

            def add_wrapper(*args, **kwargs):
                self.__add_for_deletion(args[0])
                return original_add(*args, **kwargs)

            self._db_session.add = add_wrapper
        return self._db_session

    @property
    def to_delete(self):
        """
        Get the list of model instances that will be deleted upon each unit test being torn down.
        :return: the list of model instances that will be deleted upon each unit test being torn down.
        """
        return self._to_delete

    @property
    def transaction(self):
        """
        Get the transaction to use to isolate database commits during testing.
        :return: the transaction to use to isolate database commits during testing.
        """
        return self._transaction

    # Representation and Comparison
