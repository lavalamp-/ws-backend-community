# -*- coding: utf-8 -*-
from __future__ import absolute_import

import os
import ConfigParser
from datetime import timedelta

from .singleton import Singleton
from .wsdatetime import DatetimeHelper


@Singleton
class ConfigManager(object):
    """
    Singleton for handling interaction with configuration values.
    """

    # Class Members

    _mode = "config"
    globals = {}

    # Instantiation

    def __init__(self, cfg_file="tasknode/tasknode.cfg"):
        self.filename = cfg_file
        self.config = None
        if os.path.exists(cfg_file) and os.path.isfile(cfg_file):
            self.conf_path = os.path.abspath(cfg_file)
            self.refresh()

    # Static Methods

    # Class Methods

    # Public Methods

    def refresh(self):
        """
        Refresh config file settings.
        :return: None
        """
        self.config = ConfigParser.SafeConfigParser()
        with open(self.conf_path, 'r') as fp:
            self.config.readfp(fp)

    # Protected Methods

    # Private Methods

    def __get_bool(self, section, name):
        """
        Get a boolean value from the specified config value denoted by section and name.
        :param section: The section containing the configuration value.
        :param name: The name of the configuration value.
        :return: The configuration value specified by section and name in boolean format.
        """
        return True if self.__get_value(section, name) == "True" else False

    def __get_float(self, section, name):
        """
        Get a float value from the specified config value denoted by section and name.
        :param section: The section containing the configuration value.
        :param name: The name of the configuration value.
        :return: The configuration value specified by section and name in float format.
        """
        return float(self.__get_value(section, name))

    def __get_int(self, section, name):
        """
        Get an integer value from the specified config value denoted by section and name.
        :param section: The section containing the configuration value.
        :param name: The name of the configuration value.
        :return: The configuration value specified by section and name in integer format.
        """
        return int(self.__get_value(section, name))

    def __get_value(self, section, name):
        """
        Get the value specified by section and name from the configured source for configuration information.
        :param section: The section containing the configuration value.
        :param name: The name of the configuration value.
        :return: The value associated with the specified section and name.
        """
        if self._mode == "env":
            key = "WEBSIGHT_ENV_" + name.upper()
            return os.environ[key]
        elif self._mode == "config":
            return self.config.get(section, name)
        else:
            raise ValueError(
                "ConfigManager was configured to read config values from neither the environment nor "
                "a config file. Mode was %s."
                % (self._mode,)
            )

    def __get_string(self, section, name):
        """
        Get a string value from the specified config value denoted by section and name.
        :param section: The section containing the configuration value.
        :param name: The name of the configuration value.
        :return: The configuration value specified by section and name in string format.
        """
        return str(self.__get_value(section, name))

    # Properties

    @property
    def aws_default_region(self):
        """
        Get the default region to use when interacting with AWS services.
        :return: the default region to use when interacting with AWS services.
        """
        return self.__get_string("AWS", "aws_default_region")

    @property
    def aws_key_id(self):
        """
        Get the AWS access key ID to use to communicate with AWS services.
        :return: the AWS access key ID to use to communicate with AWS services.
        """
        return self.__get_string("AWS", "aws_key_id")

    @property
    def aws_secret_key(self):
        """
        Get the AWS secret key to use to communicate with AWS services.
        :return: the AWS secret key to use to communicate with AWS services.
        """
        return self.__get_string("AWS", "aws_secret_key")

    @property
    def aws_s3_default_acl(self):
        """
        Get the default ACL to apply to all things uploaded to AWS S3.
        :return: the default ACL to apply to all things uploaded to AWS S3.
        """
        return self.__get_string("AWS", "aws_s3_default_acl")

    @property
    def celery_app_name(self):
        """
        Gets the application name to use for the Celery application running on Task nodes.
        :return: The application name to use for the Celery application running on Task nodes.
        """
        return self.__get_string("Celery", "celery_app_name")

    @property
    def celery_broker_url(self):
        """
        Gets the broker URL to use for Celery task nodes.
        :return: The broker URL to use for Celery task nodes.
        """
        return "amqp://%s:%s@%s:%s/%s" % \
               (
                   self.celery_user,
                   self.celery_password,
                   self.celery_host,
                   self.celery_port,
                   self.celery_virtual_host,
               )

    @property
    def celery_enable_utc(self):
        """
        Get whether or not to force all Celery logging to use UTC time zone.
        :return: True if Celery should be forced to use UTC time zone, False otherwise.
        """
        return self.__get_bool("Celery", "celery_enable_utc")

    @property
    def celery_es_update_delay(self):
        """
        Get the amount of time in seconds that Celery workers should wait for Elasticsearch to be
        updated when they rely on data indexed during a previous task.
        :return: the amount of time in seconds that Celery workers should wait for Elasticsearch to
        be updated when they rely on data indexed during a previous task.
        """
        return self.__get_int("Celery", "celery_es_update_delay")

    @property
    def celery_host(self):
        """
        Get the hostname of the machine that is running the RabbitMQ server.
        :return: The hostname of the machine that is running the RabbitMQ server.
        """
        return self.__get_string("Celery", "celery_host")

    @property
    def celery_max_tasks_per_child(self):
        """
        Get the maximum number of tasks that should be run by a single Celery worker before killing
        that worker and creating a new one.
        :return: The maximum number of tasks that should be run by a single Celery worker before killing
        that worker and creating a new one.
        """
        return self.__get_int("Celery", "celeryd_max_tasks_per_child")

    @property
    def celery_message_compression(self):
        """
        Get the type of compression that Celery should use during message passing.
        :return: The type of compression that Celery should use during message passing.
        """
        return self.__get_string("Celery", "celery_message_compression")

    @property
    def celery_password(self):
        """
        Get the password for connecting to the Celery broker.
        :return: The password for connecting to the Celery broker.
        """
        return self.__get_string("Celery", "celery_pass")

    @property
    def celery_port(self):
        """
        Get the port where the RabbitMQ server resides.
        :return: The port where the RabbitMQ server resides.
        """
        return self.__get_int("Celery", "celery_port")

    @property
    def celeryd_prefetch_multiplier(self):
        """
        Get the prefetch multiplier to provide Celery workers. This value determines how many tasks
        should be fetched for each Celery process prior to execution of those tasks starting.
        :return: The prefetch multiplier to provide Celery workers.
        """
        return self.__get_int("Celery", "celeryd_prefetch_multiplier")

    @property
    def celery_priority_queue_name(self):
        """
        Get the name of the queue that priority tasks should be placed in.
        :return: the name of the queue that priority tasks should be placed in.
        """
        return self.__get_string("Celery", "celery_priority_queue_name")

    @property
    def celery_redirect_stdouts(self):
        """
        Get whether or not Celery should redirect stdout and stderr to the log files.
        :return: True if Celery should redirect stdout and stderr to log files, False otherwise.
        """
        return self.__get_bool("Celery", "celery_redirect_stdouts")

    @property
    def celery_results_backend(self):
        """
        Get a connection string for where celery should store its results.
        :return: a connection string for where celery should store its results.
        """
        return "redis://%s:%s" % (self.redis_host, self.redis_port)

    @property
    def celery_retry_delay(self):
        """
        Get the amount of time in seconds that Celery tasks should wait before retrying.
        :return: the amount of time in seconds that Celery tasks should wait before retrying.
        """
        return self.__get_int("Celery", "celery_retry_delay")

    @property
    def celery_task_serializer(self):
        """
        Get the serializer type that Celery should use when serializing tasks.
        :return: The serializer type that Celery should use when serializing tasks.
        """
        return self.__get_string("Celery", "celery_task_serializer")

    @property
    def celery_track_started(self):
        """
        Get whether or not Celery task nodes should keep track of which tasks have been
        started.
        :return: True if Celery task nodes should keep track of which tasks have been started,
        False otherwise.
        """
        return self.__get_string("Celery", "celery_track_started")

    @property
    def celery_user(self):
        """
        Get the username for connecting to the Celery broker.
        :return: The username for connecting to the Celery broker.
        """
        return self.__get_string("Celery", "celery_user")

    @property
    def celery_virtual_host(self):
        """
        Get the virtual host that should be used to access the proper Celery queues.
        :return: The virtual host that should be used to access the proper Celery queues.
        """
        return self.__get_string("Celery", "celery_virtual_host")

    @property
    def celery_worker_pool(self):
        """
        Get a string representing the worker pool type to use with Celery.
        :return: a string representing the worker pool type to use with Celery.
        """
        return self.__get_string("Celery", "celery_worker_pool")

    @property
    def crawling_allow_all_error_codes(self):
        """
        Get whether or not to allow all error codes while crawling.
        :return: whether or not to allow all error codes while crawling.
        """
        return self.__get_bool("Crawling", "crawling_allow_all_error_codes")

    @property
    def crawling_bot_name(self):
        """
        Get a string representing the bot name to use for crawling.
        :return: a string representing the bot name to use for crawling.
        """
        return self.__get_string("Crawling", "crawling_bot_name")

    @property
    def crawling_concurrent_items(self):
        """
        Get the maximum number of items that should be in the Scrapy processing pipeline.
        :return: the maximum number of items that should be in the Scrapy processing pipeline.
        """
        return self.__get_int("Crawling", "crawling_concurrent_items")

    @property
    def crawling_concurrent_requests(self):
        """
        Get the maximum number of concurrent requests that Scrapy should send.
        :return: the maximum number of concurrent requests that Scrapy should send.
        """
        return self.__get_int("Crawling", "crawling_concurrent_requests")

    @property
    def crawling_depth_limit(self):
        """
        Get the depth limit that should be enforced when crawling.
        :return: the depth limit that should be enforced when crawling.
        """
        return self.__get_bool("Crawling", "crawling_depth_limit")

    @property
    def crawling_depth_priority(self):
        """
        Get the crawling depth priority to use in Scrapy.
        :return: the crawling depth priority to use in Scrapy.
        """
        return self.__get_bool("Crawling", "crawling_depth_priority")

    @property
    def crawling_enable_telnet_console(self):
        """
        Get whether or not to enable the Scrapy telnet console while crawling.
        :return: whether or not to enable the Scrapy telnet console while crawling.
        """
        return self.__get_bool("Crawling", "crawling_enable_telnet_console")

    @property
    def crawling_local_storage_buffer_size(self):
        """
        Get the maximum number of scraped items that should be stored in the local
        file writer pipeline before writing the items to disk.
        :return: the maximum number of scraped items that should be stored in the local
        file writer pipeline before writing the items to disk.
        """
        return self.__get_int("Crawling", "crawling_local_storage_buffer_size")

    @property
    def crawling_max_crawl_time(self):
        """
        Get the maximum amount of time in seconds to allow crawling to continue.
        :return: the maximum amount of time in seconds to allow crawling to continue.
        """
        return self.__get_int("Crawling", "crawling_max_crawl_time")

    @property
    def crawling_max_download_size(self):
        """
        Get the maximum size of resources to download with Scrapy.
        :return: the maximum size of resources to download with Scrapy.
        """
        return self.__get_int("Crawling", "crawling_max_download_size")

    @property
    def crawling_max_index_size(self):
        """
        Get the maximum size of resources that should be indexed in Elasticsearch after scraping.
        :return: the maximum size of resources that should be indexed in Elasticsearch after scraping.
        """
        return self.__get_int("Crawling", "crawling_max_index_size")

    @property
    def crawling_track_references(self):
        """
        Get whether or not to track what HTTP references are crawled with Scrapy.
        :return: whether or not to track what HTTP references are crawled with Scrapy.
        """
        return self.__get_bool("Crawling", "crawling_track_references")

    @property
    def crawling_user_agent(self):
        """
        Get the user agent to use by default when crawling.
        :return: the user agent to use by default when crawling.
        """
        return self.__get_string("Crawling", "crawling_user_agent")

    @property
    def db_connection_string(self):
        """
        Get the connection string to use to connect to the database.
        :return: the connection string to use to connect to the database.
        """
        return "%s://%s:%s@%s:%s/%s" % (
            self.db_scheme,
            self.db_user,
            self.db_password,
            self.db_host,
            self.db_port,
            self.db_name,
        )

    @property
    def db_host(self):
        """
        Get the hostname address where the database resides.
        :return: the hostname address where the database resides.
        """
        return self.__get_string("Database", "db_host")

    @property
    def db_name(self):
        """
        Get the database name that Web Sight should use.
        :return: the database name that Web Sight should use.
        """
        return self.__get_string("Database", "db_name")

    @property
    def db_password(self):
        """
        Get the password to use to connect to the database.
        :return: the password to use to connect to the database.
        """
        return self.__get_string("Database", "db_password")

    @property
    def db_port(self):
        """
        Get the port where the database resides.
        :return: the port where the database resides.
        """
        return self.__get_int("Database", "db_port")

    @property
    def db_scheme(self):
        """
        Get the connection string scheme to use to connect to the database.
        :return: the connection string scheme to use to connect to the database.
        """
        return self.__get_string("Database", "db_scheme")

    @property
    def db_user(self):
        """
        Get the username to connect to the database with.
        :return: the username to connect to the database with.
        """
        return self.__get_string("Database", "db_user")

    @property
    def django_settings_module(self):
        """
        Get a string pointing to the Django settings module to use during Django bootstrapping.
        :return: A string pointing to the Django settings module to use during Django bootstrapping.
        """
        return self.__get_string("Django", "django_settings_module")

    @property
    def dns_dnsdb_api_host(self):
        """
        Get the API host where DNSDB queries should be sent.
        :return: the API host where DNSDB queries should be sent.
        """
        return self.__get_string("DNS", "dns_dnsdb_api_host")

    @property
    def dns_dnsdb_api_key(self):
        """
        Get the API key to use to communicate with DNSDB.
        :return: the API key to use to communicate with DNSDB.
        """
        return self.__get_string("DNS", "dns_dnsdb_api_key")

    @property
    def dns_dnsdb_ip_history_after_date(self):
        """
        Get a datetime representing the cut off time for the first point where IP history
        should be retrieved from DNS DB.
        :return: a datetime representing the cut off time for the first point where IP history
        should be retrieved from DNS DB.
        """
        return DatetimeHelper.now() - timedelta(seconds=self.dns_dnsdb_ip_history_time_in_past)

    @property
    def dns_dnsdb_ip_history_time_in_past(self):
        """
        Get the amount of time in seconds that DNSDB IP address history queries should reach
        into the past.
        :return: the amount of time in seconds that DNSDB IP address history queries should reach
        into the past.
        """
        return self.__get_int("DNS", "dns_dnsdb_ip_history_time")

    @property
    def dns_dnsdb_record_types(self):
        """
        Get a list of DNS record types to use for subdomain enumeration through DNSDB.
        :return: a list of DNS record types to use for subdomain enumeration through DNSDB.
        """
        to_return = self.__get_string("DNS", "dns_dnsdb_record_types")
        return [x.strip() for x in to_return.strip().split(",")]

    @property
    def dns_hosts_file_location(self):
        """
        Get the local file path to where the Linux hosts file resides.
        :return: the local file path to where the Linux hosts file resides.
        """
        return self.__get_string("DNS", "dns_hosts_file_location")

    @property
    def dns_resolver_timeout(self):
        """
        Get the amount of time in seconds that berserker_resolver should wait before timing out.
        :return: the amount of time in seconds that berserker_resolver should wait before timing out.
        """
        return self.__get_int("DNS", "dns_resolver_timeout")

    @property
    def dns_resolver_tries(self):
        """
        Get the maximum number of tries that should be attempted by berserker_resolver before giving
        up on resolving a domain name.
        :return: the maximum number of tries that should be attempted by berserker_resolver before
        giving up on resolving a domain name.
        """
        return self.__get_int("DNS", "dns_resolver_tries")

    @property
    def es_bulk_update_max_size(self):
        """
        Get the maximum size in bytes that Elasticsearch updates should be.
        :return: the maximum size in bytes that Elasticsearch updates should be.
        """
        return self.__get_int("Elasticsearch", "es_bulk_update_max_size")

    @property
    def es_default_index(self):
        """
        Get a string representing the default Elasticsearch index.
        :return: a string representing the default Elasticsearch index.
        """
        return self.__get_string("Elasticsearch", "es_default_index")

    @property
    def es_host(self):
        """
        Get the host to connect to for Elasticsearch.
        :return: the host to connect to for Elasticsearch.
        """
        return self.__get_string("Elasticsearch", "es_host")

    @property
    def es_max_query_size(self):
        """
        Get the maximum allowed size for Elasticsearch queries.
        :return: the maximum allowed size for Elasticsearch queries.
        """
        return self.__get_int("Elasticsearch", "es_max_query_size")

    @property
    def es_password(self):
        """
        Get the password to connect to Elasticsearch with.
        :return: the password to connect to Elasticsearch with.
        """
        return self.__get_string("Elasticsearch", "es_password")

    @property
    def es_port(self):
        """
        Get the port to connect to Elasticsearch on.
        :return: the port to connect to Elasticsearch on.
        """
        return self.__get_int("Elasticsearch", "es_port")

    @property
    def es_scripting_language(self):
        """
        Get the default scripting language to use with Elasticsearch scripts.
        :return: the default scripting language to use with Elasticsearch scripts.
        """
        return self.__get_string("Elasticsearch", "es_scripting_language")

    @property
    def es_url(self):
        """
        Get the URL to use to connect to the Elasticsearch instance.
        :return: the URL to use to connect to the Elasticsearch instance.
        """
        return "%s://%s:%s" % (
            "https" if self.es_use_ssl else "http",
            # self.es_username,
            # self.es_password,
            self.es_host,
            self.es_port,
        )

    @property
    def es_use_http_auth(self):
        """
        Get whether or not to use HTTP authentication to the Elasticsearch service.
        :return: whether or not to use HTTP authentication to the Elasticsearch service.
        """
        return self.__get_bool("Elasticsearch", "es_use_http_auth")

    @property
    def es_username(self):
        """
        Get the username to connect to Elasticsearch with.
        :return: the username to connect to Elasticsearch with.
        """
        return self.__get_string("Elasticsearch", "es_username")

    @property
    def es_user_info_index(self):
        """
        Get a string representing the index where all of information related to user activities is stored.
        :return: a string representing the index where all of information related to user activities is stored.
        """
        return self.__get_string("Elasticsearch", "es_user_info_index")

    @property
    def es_use_aws(self):
        """
        Get whether or not the remote Elasticsearch endpoint resides in AWS.
        :return: whether or not the remote Elasticsearch endpoint resides in AWS.
        """
        return self.__get_bool("Elasticsearch", "es_use_aws")

    @property
    def es_use_ssl(self):
        """
        Get whether or not SSL should be used to connect to Elasticsearch.
        :return: whether or not SSL should be used to connect to Elasticsearch.
        """
        return self.__get_bool("Elasticsearch", "es_use_ssl")

    @property
    def files_base_directory(self):
        """
        Get the base directory where all local files used by Web Sight are stored.
        :return: the base directory where all local files used by Web Sight are stored.
        """
        return self.__get_string("Files", "files_base_directory")

    @property
    def files_default_scan_config_path(self):
        """
        Get the local file path to where the JSON file containing the default ScanConfig objects resides.
        :return: the local file path to where the JSON file containing the default ScanConfig objects resides.
        """
        file_name = self.__get_string("Files", "files_default_scan_configs")
        return os.path.join(self.files_base_directory, file_name)

    @property
    def files_default_scan_ports_path(self):
        """
        Get the local file path to where the CSV file containing default scanning ports resides.
        :return: the local file path to where the CSV file containing default scanning ports resides.
        """
        file_name = self.__get_string("Files", "files_default_scan_ports")
        return os.path.join(self.files_base_directory, file_name)

    @property
    def files_dns_record_types_path(self):
        """
        Get the local file path to where the CSV file containing DNS record types resides.
        :return: the local file path to where the CSV file containing DNS record types resides.
        """
        file_name = self.__get_string("Files", "files_dns_record_types")
        return os.path.join(self.files_base_directory, file_name)

    @property
    def files_dns_resolvers_path(self):
        """
        Get the local file path to where the text file containing DNS resolvers used by Web Sight
         resides.
        :return: the local file path to where the text file containing DNS resolvers used by Web
         Sight resides.
        """
        file_name = self.__get_string("Files", "files_dns_resolvers")
        return os.path.join(self.files_base_directory, file_name)

    @property
    def files_extended_validation_oids_path(self):
        """
        Get the local file path to where the CSV file containing SSL ENV OIDs resides.
        :return: the local file path to where the CSV file containing SSL ENV OIDs resides.
        """
        file_name = self.__get_string("Files", "files_extended_validation_oids")
        return os.path.join(self.files_base_directory, file_name)

    @property
    def files_fingerprints_path(self):
        """
        Get the local file path to where the CSV file containing file fingerprints resides.
        :return: the local file path to where the CSV file containing file fingerprints resides.
        """
        file_name = self.__get_string("Files", "files_fingerprints")
        return os.path.join(self.files_base_directory, file_name)

    @property
    def files_networks_blacklist_path(self):
        """
        Get the local file path to where the networks blacklist file resides.
        :return: the local file path to where the networks blacklist file resides.
        """
        file_name = self.__get_string("Files", "files_networks_blacklist")
        return os.path.join(self.files_base_directory, file_name)

    @property
    def files_user_agents_path(self):
        """
        Get the local file path to where the user agents CSV file resides.
        :return: the local file path to where the user agents CSV file resides.
        """
        file_name = self.__get_string("Files", "files_user_agents")
        return os.path.join(self.files_base_directory, file_name)

    @property
    def files_tlds_path(self):
        """
        Get the local file path to where the file containing supported TLDs resides.
        :return: the local file path to where the file containing supported TLDs resides.
        """
        file_name = self.__get_string("Files", "files_tlds")
        return os.path.join(self.files_base_directory, file_name)

    @property
    def fingerprint_socket_timeout(self):
        """
        Get the amount of time in seconds that sockets should wait for responses
        and connections during service fingerprinting.
        :return: the amount of time in seconds that sockets should wait for
        responses and connections during service fingerprinting.
        """
        return self.__get_int("Fingerprinting", "fingerprint_socket_timeout")

    @property
    def fs_temporary_file_dir(self):
        """
        Gets the file path (directory) where temporary files can be created and deleted.
        :return: The file path where temporary files can be created and deleted.
        """
        return self.__get_string("Filesystem", "fs_temporary_file_dir")

    @property
    def gcp_creds_file_path(self):
        """
        Get the local file path to where the Google Cloud Platform credentials file resides.
        :return: the local file path to where the Google Cloud Platform credentials file resides.
        """
        return self.__get_string("GCP", "gcp_creds_file_path")

    @property
    def gcp_project_name(self):
        """
        Get the name of the Google Cloud Platform that Web Sight is deployed into (if using GCP).
        :return: the name of the Google Cloud Platform that Web Sight is deployed into (if using GCP).
        """
        return self.__get_string("GCP", "gcp_project_name")

    @property
    def gen_default_encoding(self):
        """
        Get the default string encoding used by Web Sight.
        :return: the default string encoding used by Web Sight.
        """
        return self.__get_string("General", "gen_default_encoding")

    @property
    def gen_password_special_chars(self):
        """
        Get a string containing all of the characters that are considered special characters
        for the purpose of password generation.
        :return: a string containing all of the characters that are considered special
        characters for the purpose of password generation.
        """
        return self.__get_string("General", "gen_password_special_chars")

    @property
    def gen_reset_password_timeout_minutes(self):
        """
        Get the number of minutes before a reset password code expires
        :return: the number of minutes
        """
        return self.__get_int("General", "gen_reset_password_timeout_minutes")

    @property
    def gen_track_malformed_html(self):
        """
        Get whether or not Web Sight should automatically upload HTML that throws parsing errors.
        :return: whether or not Web Sight should automatically upload HTML that throws parsing errors.
        """
        return self.__get_bool("General", "gen_track_malformed_html")

    @property
    def http_proxy(self):
        """
        Get a string representing an HTTP proxy url.
        :return: a string representing an HTTP proxy url.
        """
        return self.__get_string("Http", "http_proxy")

    @property
    def http_proxy_enabled(self):
        """
        Get whether or not HTTP proxying is currently enabled.
        :return: whether or not HTTP proxying is currently enabled.
        """
        return self.__get_bool("Http", "http_proxy_enabled")

    @property
    def inspection_http_connect_timeout(self):
        """
        Get the amount of time in seconds that inspector classes should wait for an HTTP connection
        before timing out.
        :return: the amount of time in seconds that inspector classes should wait for an HTTP
        connection before timing out.
        """
        return self.__get_float("Inspection", "inspection_http_connect_timeout")

    @property
    def inspection_http_read_timeout(self):
        """
        Get the amount of time in seconds that inspector classes should wait for an HTTP connection to
        finish reading data before timing out.
        :return: the amount of time in seconds that inspector classes should wait for an HTTP connection
        to finish reading data before timing out.
        """
        return self.__get_float("Inspection", "inspection_http_read_timeout")

    @property
    def inspection_http_timeout_tuple(self):
        """
        Get a tuple containing (1) the connect timeout and (2) the read timeout for HTTP connections
        issued by inspector classes.
        :return: a tuple containing (1) the connect timeout and (2) the read timeout for HTTP
        connections issued by inspector classes.
        """
        return self.inspection_http_connect_timeout, self.inspection_http_read_timeout

    @property
    def inspection_screenshot_join_timeout(self):
        """
        Get the maximum amount of time in seconds that a screenshotting task should wait before
        killing the screenshot process when screenshotting is run in a child process.
        :return: the maximum amount of time in seconds that a screenshotting task should wait
        before killing the screenshot process when screenshotting is run in a child process.
        """
        return self.__get_int("Inspection", "inspection_screenshot_join_timeout")

    @property
    def inspection_socket_connect_timeout(self):
        """
        Get the amount of time in seconds that socket connections should be waited
        on before timing out.
        :return: the amount of time in seconds that socket connections should be
        waited on before timing out.
        """
        return self.__get_int("Inspection", "inspection_socket_connect_timeout")

    @property
    def inspection_user_agent(self):
        """
        Get the user agent that should be submitted alongside requests sent via inspectors.
        :return: the user agent that should be submitted alongside requests sent via inspectors.
        """
        return self.__get_string("Inspection", "inspection_user_agent")

    @property
    def log_directory(self):
        """
        Get the local file path to where all log files associated with the Web Sight 
        application are stored.
        :return: the local file path to where all log files associated with the Web Sight 
        application are stored.
        """
        return self.__get_string("Logging", "log_directory")

    @property
    def log_base_file_path(self):
        """
        Get the local file path to where all logged data is stored.
        :return: the local file path to where all logged data is stored.
        """
        log_base_file = self.__get_string("Logging", "log_base_file")
        return os.path.join(self.log_directory, log_base_file)

    @property
    def log_base_level(self):
        """
        Get the base log level to set for the root logger.
        :return: the base log level to set for the root logger.
        """
        from .conversion import ConversionHelper
        level_string = self.__get_string("Logging", "log_base_level")
        return ConversionHelper.string_to_log_level(level_string)

    @property
    def log_crawling_file_path(self):
        """
        Get the local file path to where all logged data generated by crawling is stored.
        :return: the local file path to where all logged data generated by crawling is stored.
        """
        log_crawling_file = self.__get_string("Logging", "log_crawling_file")
        return os.path.join(self.log_directory, log_crawling_file)

    @property
    def log_crawling_level(self):
        """
        Get the log level that Scrapy should use.
        :return: the log level that Scrapy should use.
        """
        from .conversion import ConversionHelper
        level_string = self.__get_string("Logging", "log_crawling_level")
        return ConversionHelper.string_to_log_level(level_string)

    @property
    def log_error_file_path(self):
        """
        Get the local file path to where all errors thrown by Web Sight are stored.
        :return: the local file path to where all errors thrown by Web Sight are stored.
        """
        error_file = self.__get_string("Logging", "log_error_file")
        return os.path.join(self.log_directory, error_file)

    @property
    def log_max_bytes(self):
        """
        Get the maximum number of bytes that a single log file should contain.
        :return: the maximum number of bytes that a single log file should contain.
        """
        return self.__get_int("Logging", "log_max_bytes")

    @property
    def log_max_files(self):
        """
        Get the maximum number of rotated log files that should be used by Web Sight.
        :return: the maximum number of rotated log files that should be used by Web Sight.
        """
        return self.__get_int("Logging", "log_max_files")

    @property
    def log_task_file_path(self):
        """
        Get the local file path to where all logged data generated by tasks is stored.
        :return: the local file path to where all logged data generated by tasks is stored.
        """
        log_task_file = self.__get_string("Logging", "log_task_file")
        return os.path.join(self.log_directory, log_task_file)

    @property
    def log_task_level(self):
        """
        Get the log level that Scrapy should use.
        :return: the log level that Scrapy should use.
        """
        from .conversion import ConversionHelper
        level_string = self.__get_string("Logging", "log_task_level")
        return ConversionHelper.string_to_log_level(level_string)

    @property
    def pubsub_connector_type(self):
        """
        Get the type of connector that should be used.
        :return: the type of connector that should be used.
        """
        to_return = self.__get_string("PubSub", "pubsub_connector_type")
        from .validation import ValidationHelper
        ValidationHelper.validate_in(to_return, ["gcp"])
        return to_return

    @property
    def pubsub_enabled(self):
        """
        Get whether or not Web Sight should receive messages from and publish messages to a pubsub.
        :return: whether or not Web Sight should receive messages from and publish messages to a pubsub.
        """
        return self.__get_bool("PubSub", "pubsub_enabled")

    @property
    def pubsub_poll_interval(self):
        """
        Get the amount of time in seconds between checks for the PubSub message queue.
        :return: the amount of time in seconds between checks for the PubSub message queue.
        """
        return self.__get_float("PubSub", "pubsub_poll_interval")

    @property
    def pubsub_publish_topic(self):
        """
        Get the pubsub topic that Web Sight should publish messages to.
        :return: the pubsub topic that Web Sight should publish messages to.
        """
        return self.__get_string("PubSub", "pubsub_publish_topic")

    @property
    def pubsub_receive_topic(self):
        """
        Get the pubsub topic that Web Sight should listen to for messages.
        :return: the pubsub topic that Web Sight should listen to for messages.
        """
        return self.__get_string("PubSub", "pubsub_receive_topic")

    @property
    def pubsub_retrieve_interval(self):
        """
        Get the interval that reading messages from the PubSub should wait during a
        message retrieval task.
        :return: the interval that reading messages from the PubSub should wait during a
        message retrieval task.
        """
        return self.__get_int("PubSub", "pubsub_retrieve_interval")

    @property
    def redis_host(self):
        """
        Get the hostname of the machine that is running the Redis server.
        :return: The hostname of the machine that is running the Redis server.
        """
        return self.__get_string("Redis", "redis_host")

    @property
    def redis_port(self):
        """
        Get the post for the Redis server used by DataHound.
        :return: The post for the Redis server used by DataHound.
        """
        return self.__get_int("Redis", "redis_port")

    @property
    def rest_domain(self):
        """
        Get the domain where the front-end application currently resides.
        :return: the domain where the front-end application currently resides.
        """
        return self.__get_string("Rest", "rest_domain")

    @property
    def rest_domains_file_cutoff(self):
        """
        Get the maximum number of lines in an uploaded domains file to process without
        kicking processing back to a task.
        :return: the maximum number of lines in an uploaded domains file to process without
        kicking processing back to a task.
        """
        return self.__get_int("Rest", "rest_domains_file_cutoff")

    @property
    def rest_max_network_mask_length(self):
        """
        Get the maximum length that a network mask must be for Rest API requests.
        :return: the maximum length that a network mask must be for Rest API requests.
        """
        return self.__get_int("Rest", "rest_max_network_mask_length")

    @property
    def rest_min_network_mask_length(self):
        """
        Get the minimum length that a network mask must be for Rest API requests.
        :return: the minimum length that a network mask must be for Rest API requests.
        """
        return self.__get_int("Rest", "rest_min_network_mask_length")

    @property
    def selenium_screenshot_delay(self):
        """
        Get the amount of time in seconds that Selenium should wait between requesting a
        URL and taking a screenshot.
        :return: the amount of time in seconds that Selenium should wait between requesting a
        URL and taking a screenshot.
        """
        return self.__get_int("Selenium", "selenium_screenshot_delay")

    @property
    def selenium_screenshot_format(self):
        """
        Get the output format that Selenium should save screenshots in.
        :return: the output format that Selenium should save screenshots in.
        """
        return self.__get_string("Selenium", "selenium_screenshot_format")

    @property
    def selenium_window_height(self):
        """
        Get the height (in pixels) that the Selenium viewing window should be.
        :return: the height (in pixels) that the Selenium viewing window should be.
        """
        return self.__get_int("Selenium", "selenium_window_height")

    @property
    def selenium_window_width(self):
        """
        Get the width (in pixels) that the Selenium viewing window should be.
        :return: the width (in pixels) that the Selenium viewing window should be.
        """
        return self.__get_int("Selenium", "selenium_window_width")

    @property
    def smtp_endpoint(self):
        """
        Get a string containing the endpoint that Web Sight should connect to to send emails.
        :return: a string containing the endpoint that Web Sight should connect to to send emails.
        """
        return "%s:%s" % (self.smtp_host, self.smtp_port)

    @property
    def smtp_host(self):
        """
        Get the default host for the websight.io smtp account
        :return: the default host for the websight.io smtp account
        """
        return self.__get_string("SMTP", "smtp_host")

    @property
    def smtp_password(self):
        """
        Get the default password for the websight.io smtp account
        :return: the default password for the websight.io smtp account
        """
        return self.__get_string("SMTP", "smtp_password")

    @property
    def smtp_port(self):
        """
        Get the default port for the smtp host
        :return: the default smtp port
        """
        return self.__get_int("SMTP", "smtp_port")

    @property
    def smtp_username(self):
        """
        Get the default username for the websight.io smtp account
        :return: the default username for the websight.io smtp account
        """
        return self.__get_string("SMTP", "smtp_username")

    @property
    def storage_bad_html_path(self):
        """
        Get the file path in which poorly-formed HTML should be stored in the cloud storage backend.
        :return: the file path in which poorly-formed HTML should be stored in the cloud storage backend.
        """
        return self.__get_string("Storage", "storage_bad_html_path")

    @property
    def storage_bucket(self):
        """
        Get the default bucket name that Web Sight should use for cloud storage.
        :return: the default bucket name that Web Sight should use for cloud storage.
        """
        return self.__get_string("Storage", "storage_bucket")

    @property
    def storage_certificates_path(self):
        """
        Get the file path in which SSL certificates should be stored in the cloud storage backend.
        :return: the file path in which SSL certificates should be stored in the cloud storage backend.
        """
        return self.__get_string("Storage", "storage_certificates_path")

    @property
    def storage_platform(self):
        """
        Get a string depicting which cloud platform to use for file storage.
        :return: a string depicting which cloud platform to use for file storage.
        """
        return self.__get_string("Storage", "storage_platform")

    @property
    def storage_screenshots_path(self):
        """
        Get the file path in which screenshots should be stored in the cloud storage backend.
        :return: the file path in which screenshots should be stored in the cloud storage backend.
        """
        return self.__get_string("Storage", "storage_screenshots_path")

    @property
    def storage_signed_url_duration(self):
        """
        Get the amount of time in seconds that a signed URL should remain valid for.
        :return: the amount of time in seconds that a signed URL should remain valid for.
        """
        return self.__get_int("Storage", "storage_signed_url_duration")

    @property
    def storage_uploads_path(self):
        """
        Get the file path in which user uploads should be stored in the cloud storage backend.
        :return: the file path in which user uploads should be stored in the cloud storage backend.
        """
        return self.__get_string("Storage", "storage_uploads_path")

    @property
    def task_default_index(self):
        """
        Get the default index that Tasks should use when logging information about
        their success or failure.
        :return: the default index that Tasks should use when logging information about
        their success or failure.
        """
        return self.__get_string("Tasks", "task_default_index")

    @property
    def task_domain_scanning_interval(self):
        """
        Get the amount of time in seconds that should pass between domain scans.
        :return: the amount of time in seconds that should pass between domain scans.
        """
        return self.__get_int("Tasks", "task_domain_scanning_interval")

    @property
    def task_enforce_domain_name_scan_interval(self):
        """
        Get whether or not the domain name scan interval should be enforced.
        :return: whether or not the domain name scan interval should be enforced.
        """
        return self.__get_bool("Tasks", "task_enforce_domain_name_scan_interval")

    @property
    def task_enforce_ip_address_scan_interval(self):
        """
        Get whether or not the IP address scan interval should be enforced.
        :return: whether or not the IP address scan interval should be enforced.
        """
        return self.__get_bool("Tasks", "task_enforce_ip_address_scan_interval")

    @property
    def task_enforce_network_service_scan_interval(self):
        """
        Get whether or not the network service scan interval should be enforced (ie: disallow
        network services from being scanned more less than X seconds apart).
        :return: whether or not the network service scan interval should be enforced (ie: disallow
        network services from being scanned more less than X seconds apart).
        """
        return self.__get_bool("Tasks", "task_enforce_network_service_scan_interval")

    @property
    def task_enforce_web_service_scan_interval(self):
        """
        Get whether or not the web service scan interval should be enforced.
        :return: whether or not the web service scan interval should be enforced.
        """
        return self.__get_bool("Tasks", "task_enforce_web_service_scan_interval")

    @property
    def task_minimum_domain_name_scan_interval(self):
        """
        Get the minimum amount of time in seconds that should be permitted between when a domain name
        scan can be run twice on the same domain name.
        :return: the minimum amount of time in seconds that should be permitted between when a
        domain name scan can be run twice on the same domain name.
        """
        return self.__get_int("Tasks", "task_minimum_domain_name_scan_interval")

    @property
    def task_minimum_ip_address_scan_interval(self):
        """
        Get the minimum amount of time in seconds that should be permitted between scanning the same IP
        address multiple times for an organization.
        :return: the minimum amount of time in seconds that should be permitted between scanning
        the same IP address multiple times for an organization.
        """
        return self.__get_int("Tasks", "task_minimum_ip_address_scan_interval")

    @property
    def task_minimum_network_service_scan_interval(self):
        """
        Get the minimum amount of time in seconds that should be permitted between when a network service
        scan can be run twice on the same endpoint.
        :return: the minimum amount of time in seconds that should be permitted between when a network
        service scan can be run twice on the same endpoint.
        """
        return self.__get_int("Tasks", "task_minimum_network_service_scan_interval")

    @property
    def task_minimum_web_service_scan_interval(self):
        """
        Get the minimum amount of time in seconds that should be permitted between scanning the same web
        service multiple times for an organization.
        :return: the minimum amount of time in seconds that should be permitted between scanning
        the same web service multiple times for an organization.
        """
        return self.__get_int("Tasks", "task_minimum_web_service_scan_interval")

    @property
    def task_network_scanning_interval(self):
        """
        Get the amount of time in seconds that should pass between scans of a network.
        :return: the amount of time in seconds that should pass between scans of a network.
        """
        return self.__get_int("Tasks", "task_network_scanning_interval")

    @property
    def task_network_service_monitoring_enabled(self):
        """
        Get whether or not network service monitoring is currently enabled.
        :return: whether or not network service monitoring is currently enabled.
        """
        return self.__get_bool("Tasks", "task_service_monitoring_enabled")

    # Representation and Comparison

