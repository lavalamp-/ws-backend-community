# -*- coding: utf-8 -*-
from __future__ import absolute_import

import amqp
import socket
import botocore.exceptions
import logging

from .smtp.smtp import SmtpEmailHelper
from .sqlalchemy import get_sa_session, ZmapConfig, WsUser, NmapConfig
from .config import ConfigManager
from .filesystem import PathHelper

config = ConfigManager.instance()
logger = logging.getLogger(__name__)


class DeployChecker(object):
    """
    This is a class for checking to see that all connectivity required for application usage is
    available, that all third-party integrations are working, and that all required database models
    are populated.
    """

    # Class Members

    # Instantiation

    def __init__(self):
        self._database_available = None
        self._database_connectable = None
        self._redis_available = None
        self._redis_connectable = None
        self._rabbitmq_available = None
        self._rabbitmq_connectable = None
        self._elasticsearch_available = None
        self._elasticsearch_connectable = None
        self._s3_available = None
        self._s3_connectable = None
        self._zmap_configs_present = None
        self._nmap_configs_present = None
        self._mail_server_available = None
        self._mail_server_connectable = None
        self._user_index_present = None

    # Static Methods

    # Class Methods

    # Public Methods

    def print_status(self):
        """
        Print the current state of all the connectivity and deployment checks from this host.
        :return: None
        """
        print("Database:\t\t%s\t%s" % (self.database_connectable, self.database_available))
        print("Redis:\t\t\t%s\t%s" % (self.redis_connectable, self.redis_available))
        print("RabbitMQ:\t\t%s\t%s" % (self.rabbitmq_connectable, self.rabbitmq_available))
        print("Elasticsearch:\t\t%s\t%s" % (self.elasticsearch_connectable, self.elasticsearch_connectable))
        print("S3:\t\t\t%s\t%s" % (self.s3_connectable, self.s3_available))
        print("Zmap:\t\t\t%s\t%s" % (self.zmap_configs_present, self.zmap_present))
        print("Nmap:\t\t\t%s\t%s" % (self.nmap_configs_present, self.nmap_present))
        print("SMTP:\t\t\t%s\t%s" % (self.mail_server_connectable, self.mail_server_available))
        print("Indices:\t\t%s" % (self.user_index_present,))
        print("PhantomJS:\t\t%s" % (self.phantomjs_present,))

    # Protected Methods

    # Private Methods

    def __check_for_command_line_tool(self, tool_name):
        """
        Check to see if the given command line tool is currently available on the tested
        machine.
        :return: True if the given command line tool is currently available on the tested machine,
        False otherwise.
        """
        return PathHelper.is_executable_in_path(tool_name)

    def __check_for_database_availability(self):
        """
        Check to see if a database query can be made against the configured database.
        :return: True if a database query can be made against the configured database, False otherwise.
        """
        session = get_sa_session()
        result = session.execute("select 'Hello World';")
        session.close()
        return result.fetchall()[0][0] == "Hello World"

    def __check_for_database_connectivity(self):
        """
        Check to see if a TCP connection can be made to the configured database.
        :return: True if a TCP connection can be made to the configured database, False otherwise.
        """
        return self.__check_for_tcp_connectivity(endpoint=config.db_host, port=config.db_port)

    def __check_for_elasticsearch_availability(self):
        """
        Check to see if the configured Elasticsearch service can be interacted with.
        :return: True if the configured Elasticsearch service can be interacted with, False otherwise.
        """
        from wselasticsearch.helper import ElasticsearchHelper
        helper = ElasticsearchHelper.instance()
        try:
            info = helper.get_info()
            return bool(info)
        except UnboundLocalError:
            return False

    def __check_for_elasticsearch_connectivity(self):
        """
        Check to see if a TCP connection can be made to the Elasticsearch endpoint.
        :return: True if a TCP connection can be made to the Elasticsearch endpoint, False otherwise.
        """
        return self.__check_for_tcp_connectivity(endpoint=config.es_host, port=config.es_port)

    def __check_for_mail_server_availability(self):
        """
        Check to see if Web Sight can communicate with the configured mail server.
        :return: True if Web Sight can communicate with the configured mail server, False otherwise.
        """
        smtp_helper = SmtpEmailHelper.instance()
        return smtp_helper.test_authentication()

    def __check_for_mail_server_connectivity(self):
        """
        Check to see if a TCP connection can be made to the configured mail server.
        :return: True if a TCP connection can be made to the configured mail server, False otherwise.
        """
        return self.__check_for_tcp_connectivity(endpoint=config.smtp_host, port=config.smtp_port)

    def __check_for_nmap_configs(self):
        """
        Check to see if the default Nmap configuration records are currently in the database.
        :return: True if the default Nmap configuration records are currently in the database, False
        otherwise.
        """
        session = get_sa_session()
        config_count = session.query(NmapConfig).filter(NmapConfig.name == "default").count()
        session.close()
        return config_count > 0

    def __check_for_rabbitmq_availability(self):
        """
        Check to see if the RabbitMQ server is available to run commands against.
        :return: True if the RabbitMQ server is available to run commands against, False otherwise.
        """
        try:
            connection = amqp.connection.Connection(
                host="%s:%s" % (config.celery_host, config.celery_port),
                userid=config.celery_user,
                password=config.celery_password,
                virtual_host=config.celery_virtual_host,
            )
            connection.close()
            return True
        except Exception as e:
            if e not in amqp.exceptions.ERROR_MAP.values():
                raise e
            return False

    def __check_for_rabbitmq_connectivity(self):
        """
        Check to see if a TCP connection can be made to the configured RabbitMQ endpoint.
        :return: True if a TCP connection can be made to the configured RabbitMQ endpoint, False otherwise.
        """
        return self.__check_for_tcp_connectivity(endpoint=config.celery_host, port=config.celery_port)

    def __check_for_redis_availability(self):
        """
        Check to see if a query can be run against the configured Redis server.
        :return: True if a query can be run against the configured Redis server, False otherwise.
        """
        from lib import RedisHelper
        redis_helper = RedisHelper.instance()
        redis_helper.set(key="test", value="FOOBAR 1 2 3")
        result = redis_helper.get("test")
        return result == "FOOBAR 1 2 3"

    def __check_for_redis_connectivity(self):
        """
        Check to see if a TCP connection can be made to the configured Redis server.
        :return: True if a TCP connection can be made to the configured Redis server, False otherwise.
        """
        return self.__check_for_tcp_connectivity(endpoint=config.redis_host, port=config.redis_port)

    def __check_for_s3_availability(self):
        """
        Check to see if the configured user can correctly query Amazon S3.
        :return: True if the configured user can correctly query Amazon S3, False otherwise.
        """
        from .aws import S3Helper
        helper = S3Helper.instance()
        try:
            helper.get_buckets()
            return True
        except botocore.exceptions.ClientError:
            return False

    def __check_for_s3_connectivity(self):
        """
        Check to see if a TCP connection can be made to Amazon S3.
        :return: True if a TCP connection can be made to Amazon S3, False otherwise.
        """
        return self.__check_for_tcp_connectivity(endpoint="s3.amazonaws.com", port=443)

    def __check_for_tcp_connectivity(self, endpoint=None, port=None):
        """
        Check to see if a TCP connection can be established to the given endpoint.
        :param endpoint: The endpoint to attempt connecting to.
        :param port: The port to attempt connecting to.
        :return: True if the endpoint could be connected to, False otherwise.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(config.inspection_socket_connect_timeout)
        try:
            s.connect((endpoint, port))
            s.close()
            return True
        except socket.error:
            return False

    def __check_for_user_index(self):
        """
        Check to see if the user information index is currently present in Elasticsearch.
        :return: True if the user information index is currently present in Elasticsearch, False otherwise.
        """
        from wselasticsearch.helper import ElasticsearchHelper
        es_helper = ElasticsearchHelper.instance()
        return config.es_user_info_index in es_helper.get_indices()

    def __check_for_zmap_configs(self):
        """
        Check to see if the default Zmap configuration records are currently in the database.
        :return: True if the default Zmap configuration records are currently in the database, False
        otherwise.
        """
        session = get_sa_session()
        config_count = session.query(ZmapConfig).filter(ZmapConfig.name == "default").count()
        session.close()
        return config_count > 0

    # Properties

    @property
    def database_available(self):
        """
        Get whether or not the configured database is currently accessible.
        :return: whether or not the configured database is currently accessible.
        """
        if self._database_available is None:
            if not self.database_connectable:
                self._database_available = False
            else:
                self._database_available = self.__check_for_database_availability()
        return self._database_available

    @property
    def database_connectable(self):
        """
        Get whether or not the database server can currently be connected to.
        :return: whether or not the database server can currently be connected to.
        """
        if self._database_connectable is None:
            self._database_connectable = self.__check_for_database_connectivity()
        return self._database_connectable

    @property
    def elasticsearch_available(self):
        """
        Get whether or not Elasticsearch is currently available with the configured credentials.
        :return: whether or not Elasticsearch is currently available with the configured credentials.
        """
        if self._elasticsearch_available is None:
            if not self.elasticsearch_connectable:
                self._elasticsearch_available = False
            else:
                self._elasticsearch_available = self.__check_for_elasticsearch_availability()
        return self._elasticsearch_available

    @property
    def elasticsearch_connectable(self):
        """
        Get whether or not a TCP connection can be made to the Elasticsearch endpoint.
        :return: whether or not a TCP connection can be made to the Elasticsearch endpoint.
        """
        if self._elasticsearch_available is None:
            self._elasticsearch_connectable = self.__check_for_elasticsearch_connectivity()
        return self._elasticsearch_connectable

    @property
    def is_ready_for_api_deploy(self):
        """
        Check to see whether or not all systems are go for deploying the API to this host.
        :return: True if all systems are go for deploying the API to this host, False otherwise.
        """
        return self.database_connectable \
               and self.database_available \
               and self.rabbitmq_connectable \
               and self.rabbitmq_available \
               and self.elasticsearch_connectable \
               and self.elasticsearch_available \
               and self.s3_connectable \
               and self.s3_available \
               and self.zmap_configs_present \
               and self.mail_server_connectable \
               and self.mail_server_available \
               and self.user_index_present

    @property
    def is_ready_for_tasknode_deploy(self):
        """
        Get whether or not all systems are go for deploying a tasknode to this host.
        :return: whether or not all systems are go for deploying a tasknode to this host.
        """
        return self.is_ready_for_api_deploy \
               and self.redis_connectable \
               and self.redis_available

    @property
    def mail_server_available(self):
        """
        Get whether or not Web Sight can currently communicate with the configured mail server.
        :return: whether or not Web Sight can currently communicate with the configured mail server.
        """
        if self._mail_server_available is None:
            if not self.mail_server_connectable:
                self._mail_server_available = False
            else:
                self._mail_server_available = self.__check_for_mail_server_availability()
        return self._mail_server_available

    @property
    def mail_server_connectable(self):
        """
        Get whether or not a TCP connection can be made to the configured mail server.
        :return: whether or not a TCP connection can be made to the configured mail server.
        """
        if self._mail_server_connectable is None:
            self._mail_server_connectable = self.__check_for_mail_server_connectivity()
        return self._mail_server_connectable

    @property
    def nmap_configs_present(self):
        """
        Get whether or not the default Nmap configuration records currently exist in the database.
        :return: whether or not the default Nmap configuration records currently exist in the database.
        """
        if self._nmap_configs_present is None:
            if not self.database_available:
                self._nmap_configs_present = False
            else:
                self._nmap_configs_present = self.__check_for_nmap_configs()
        return self._nmap_configs_present

    @property
    def nmap_present(self):
        """
        Get whether or not the nmap application is present on this machine.
        :return: whether or not the nmap application is present on this machine.
        """
        return self.__check_for_command_line_tool("nmap")

    @property
    def phantomjs_present(self):
        """
        Get whether or not PhantomJS is present on this machine.
        :return: Whether or not PhantomJS is present on this machine.
        """
        return self.__check_for_command_line_tool("phantomjs")

    @property
    def rabbitmq_available(self):
        """
        Get whether or not the RabbitMQ service is currently available.
        :return: whether or not the RabbitMQ service is currently available.
        """
        if self._rabbitmq_available is None:
            if not self.rabbitmq_connectable:
                self._rabbitmq_available = False
            else:
                self._rabbitmq_available = self.__check_for_rabbitmq_availability()
        return self._rabbitmq_available

    @property
    def rabbitmq_connectable(self):
        """
        Get whether or not a TCP connection can be made to the configured RabbitMQ server.
        :return: whether or not a TCP connection can be made to the configured RabbitMQ server.
        """
        if self._rabbitmq_connectable is None:
            self._rabbitmq_connectable = self.__check_for_rabbitmq_connectivity()
        return self._rabbitmq_connectable

    @property
    def redis_available(self):
        """
        Get whether or not the Redis server is currently accessible.
        :return: whether or not the Redis server is currently accessible.
        """
        if self._redis_available is None:
            if not self.redis_connectable:
                self._redis_available = False
            else:
                self._redis_available = self.__check_for_redis_availability()
        return self._redis_available

    @property
    def redis_connectable(self):
        """
        Get whether or not the Redis server can currently be connected to.
        :return: whether or not the Redis server can currently be connected to.
        """
        if self._redis_connectable is None:
            self._redis_connectable = self.__check_for_redis_connectivity()
        return self._redis_connectable

    @property
    def s3_available(self):
        """
        Get whether or not Amazon S3 is currently available.
        :return: whether or not Amazon S3 is currently available.
        """
        if self._s3_available is None:
            if not self.s3_connectable:
                self._s3_available = False
            else:
                self._s3_available = self.__check_for_s3_availability()
        return self._s3_available

    @property
    def s3_connectable(self):
        """
        Get whether or not a TCP connection can be made to Amazon S3.
        :return: whether or not a TCP connection can be made to Amazon S3.
        """
        if self._s3_connectable is None:
            self._s3_connectable = self.__check_for_s3_connectivity()
        return self._s3_connectable

    @property
    def user_index_present(self):
        """
        Get whether or not the index where user information is stored in Elasticsearch exists.
        :return: whether or not the index where user information is stored in Elasticsearch exists.
        """
        if self._user_index_present is None:
            if not self.s3_available:
                self._user_index_present = False
            else:
                self._user_index_present = self.__check_for_user_index()
        return self._user_index_present

    @property
    def zmap_configs_present(self):
        """
        Get whether or not the default Zmap configuration records currently
        exist in the database.
        :return: whether or not the default Zmap configuration records currently
        exist in the database.
        """
        if self._zmap_configs_present is None:
            if not self.database_available:
                self._zmap_configs_present = False
            else:
                self._zmap_configs_present = self.__check_for_zmap_configs()
        return self._zmap_configs_present

    @property
    def zmap_present(self):
        """
        Get whether or not the Zmap application is present on this machine.
        :return: whether or not the Zmap application is present on this machine.
        """
        return self.__check_for_command_line_tool("zmap")

    # Representation and Comparison
