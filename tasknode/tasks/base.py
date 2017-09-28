# -*- coding: utf-8 -*-
from __future__ import absolute_import

import time
from uuid import uuid4
from celery import Task
from celery.exceptions import Ignore
from celery.canvas import group, chord, chain, Signature
from celery.utils.log import get_task_logger

from lib import ConfigManager, RedisHelper, TempFileMixin
from lib.sqlalchemy import get_sa_session, get_endpoint_information_for_org_network_service, IpAddress, IpAddressScan, \
    NetworkService, NetworkServiceScan, WebService, WebServiceScan, Order, DomainName, DomainNameScan, Network, \
    OrganizationNetworkScan
from lib.parsing import UrlWrapper
from tasknode import websight_app

logger = get_task_logger(__name__)
config = ConfigManager.instance()


class WebSightBaseTask(Task, TempFileMixin):
    """
    A base Celery Task class for all Celery tasks defined within the Web Sight platform. This class
    contains functionality that extends the default Celery Canvas functionality to enable tasks
    to wait for subtasks before completing (without blocking processes!).
    """

    # Class Members

    abstract = True
    _redis_helper = None
    _wait_for_tag_task = None
    _start_time = None
    _task_args = None
    _task_kwargs = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        """
        Handler called after the task returns.
        :param status: Current task state.
        :param retval: Task return value/exception.
        :param task_id: Unique id of the task.
        :param args: Original arguments for the task that returned.
        :param kwargs: Original keyword arguments for the task that returned.
        :param einfo: ExceptionInfo instance, containing the traceback (if any).
        :return: None
        """
        logger.debug(
            "In %s.after_return: %s, %s, %s, %s."
            % (self.__class__.__name__, status, retval, task_id, einfo)
        )
        self.__decrement_request_tags()
        super(WebSightBaseTask, self).after_return(status, retval, task_id, args, kwargs, einfo)

    def apply_async(self, *args, **kwargs):
        """
        Override the default Celery Task apply_async to allow for the passing of
        tags to tasks.
        :param args: Positional arguments.
        :param kwargs: Keyword arguments.
        :return: The results of calling super.apply_async.
        """
        tags = kwargs.get("tags", [])
        headers = kwargs.get("headers", {})
        retries = kwargs.get("retries", 0)

        task_args, task_kwargs = args
        tags.extend(self.__get_tags_from_task_kwargs(task_kwargs))

        try:
            del kwargs["chord"]["options"]["producer"]
        except (TypeError, KeyError):
            pass
        if tags is not None and not isinstance(tags, list):
            raise ValueError(
                "Got an unexpected value for the tags keyword argument to apply_async: %s."
                % (tags,)
            )
        if len(tags) > 0:
            if retries > 0:
                logger.debug(
                    "Not incrementing tags %s as apply_async resulted from retry."
                    % (tags,)
                )
            else:
                self.__increment_tags(tags)
            headers["tags"] = tags
        kwargs["headers"] = headers
        return super(WebSightBaseTask, self).apply_async(*args, **kwargs)

    def clean_up(self):
        """
        Perform any house keeping after the task has been completed.
        :return: None
        """
        pass
        # This appears to cause some problems when using gevent as our pool, and other
        # tasks end up deleting the files used by this task. Jfc Celery is such a pain.
        # self.delete_temporary_files()

    def finish_after(self, signature=None, check_interval=config.celery_retry_delay):
        """
        Have the current task wait to finish until the tasks associated with the given
        signature have finished. Note that calling this method will invoke the signature, and that
        the waiting process polls (instead of blocks and waits).
        :param signature: The signature to wait on.
        :param check_interval: The amount of time in seconds to wait between checks of the
        given tag's value.
        :return: None
        """
        task_count = self.__count_tasks_in_signature(signature)
        if task_count == 0:
            logger.warning(
                "Attempted to wait on a signature that referenced zero tasks."
            )
            return
        else:
            tag = str(uuid4())
            self.__apply_tag_to_signature(signature=signature, tag=tag)
            signature.apply_async()
            self.wait_for_tag(tag=tag, check_interval=check_interval)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """
        This is run by the worker when the task fails.
        :param exc: The exception raised by the task.
        :param task_id: Unique id of the failed task.
        :param args: Original arguments for the task that failed.
        :param kwargs: Original keyword arguments for the task that failed.
        :param einfo: ExceptionInfo instance, containing the traceback.
        :return: None
        """
        logger.debug(
            "In %s.on_failure: %s, %s, %s."
            % (self.__class__.__name__, exc, task_id, einfo)
        )
        self.clean_up()
        super(WebSightBaseTask, self).on_failure(exc, task_id, args, kwargs, einfo)

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """
        This is run by the worker when the task is to be retried.
        :param exc: The exception sent to retry().
        :param task_id: Unique id of the retried task.
        :param args: Original arguments for the retried task.
        :param kwargs: Original keyword arguments for the retried task.
        :param einfo: ExceptionInfo instance, containing the traceback.
        :return: None
        """
        logger.debug(
            "In %s.on_retry: %s, %s, %s."
            % (self.__class__.__name__, exc, task_id, einfo)
        )
        self.clean_up()
        super(WebSightBaseTask, self).on_retry(exc, task_id, args, kwargs, einfo)

    def on_success(self, retval, task_id, args, kwargs):
        """
        Run by the worker if the task executes successfully.
        :param retval: The return value of the task.
        :param task_id: Unique id of the executed task.
        :param args: Original arguments for the executed task.
        :param kwargs: Original keyword arguments for the executed task.
        :return: None
        """
        logger.debug(
            "In %s.on_success: %s, %s."
            % (self.__class__.__name__, retval, task_id)
        )
        self.clean_up()
        super(WebSightBaseTask, self).on_success(retval, task_id, args, kwargs)

    def wait_for_es(self, duration=None):
        """
        Sleep for a configured amount of time, the purpose of which is to allow Elasticsearch to
        finish indexing any data that the current task relies upon.
        :param duration: The amount of time to wait in seconds. If None, the default to contents of
        config file.
        :return: None
        """
        delay = duration if duration is not None else config.celery_es_update_delay
        logger.info(
            "Sleeping for %s seconds to allow Elasticsearch to finish indexing."
            % (delay,)
        )
        time.sleep(delay)

    def wait_for_tag(self, tag=None, check_interval=config.celery_retry_delay):
        """
        Have this task wait until the specified tag's value is equal to zero in the configured
        back-end redis store.
        :param tag: The tag to monitor.
        :param check_interval: The time in seconds to wait between checks of the tag value.
        :return: None
        """
        logger.debug(
            "Creating wait_for_tag task in response to %s. Tag to monitor is %s."
            % (self.name, tag)
        )
        wait_request = self.__get_wait_on_tag_request(tag=tag, check_interval=check_interval)
        wait_request.apply_async(countdown=1.0)
        raise Ignore()

    # Protected Methods

    # Private Methods

    def __add_tag_to_signature(self, signature=None, tag=None):
        """
        Append the given tag to the list of tags associated with the given signature.
        :param signature: The signature to add the tag to.
        :param tag: The tag to add to the signature.
        :return: None
        """
        tags = signature.options.get("tags", [])
        tags.append(tag)
        signature.options["tags"] = tags

    def __apply_tag_to_signature(self, signature=None, tag=None):
        """
        Apply the given tag to every signature contained within the given signature.
        :param signature: The signature to apply the given tag to.
        :param tag: The tag to apply to the signature.
        :return: None
        """
        if isinstance(signature, group):
            for cur_signature in signature.tasks:
                self.__apply_tag_to_signature(signature=cur_signature, tag=tag)
        elif isinstance(signature, chain):
            for cur_signature in signature.tasks:
                self.__apply_tag_to_signature(signature=cur_signature, tag=tag)
        elif isinstance(signature, chord):
            for cur_signature in signature.tasks:
                self.__apply_tag_to_signature(signature=cur_signature, tag=tag)
            self.__apply_tag_to_signature(signature=signature.body, tag=tag)
        elif signature.__class__ == Signature:
            self.__add_tag_to_signature(signature=signature, tag=tag)
        else:
            raise TypeError(
                "Unexpected type received by __apply_tag_to_signature: %s."
                % (signature.__class__.__name__,)
            )

    def __count_tasks_in_signature(self, signature):
        """
        Count the number of tasks that are found within the referenced signature.
        :param signature: The signature to check.
        :return: The number of tasks found within the signature.
        """
        to_return = 0
        if isinstance(signature, group):
            for cur_signature in signature.tasks:
                to_return += self.__count_tasks_in_signature(cur_signature)
        elif isinstance(signature, chain):
            for cur_signature in signature.tasks:
                to_return += self.__count_tasks_in_signature(cur_signature)
        elif isinstance(signature, chord):
            for cur_signature in signature.tasks:
                to_return += self.__count_tasks_in_signature(cur_signature)
            to_return += self.__count_tasks_in_signature(signature.body)
        elif signature.__class__ == Signature:
            to_return += 1
        else:
            raise TypeError(
                "Unexpected type received by __apply_tag_to_signature: %s."
                % (signature.__class__.__name__,)
            )
        return to_return

    def __decrement_tags(self, tags):
        """
        Decrement the counters associated with all tags found in the given tags list.
        :param tags: A list of strings representing the tags associated with the task
        in question.
        :return: None
        """
        logger.debug(
            "Now decrementing tags: %s."
            % (tags,)
        )
        results = self.redis_helper.decrement_tags(tags)
        for k, v in zip(tags, results):
            logger.debug(
                "Tag %s --> %s"
                % (k, v)
            )

    def __decrement_request_tags(self):
        """
        Decrement the counters associated with all tags found in self.request.
        :return: None
        """
        self.__decrement_tags(self.request_tags)

    def __increment_tags(self, tags):
        """
        Increment the counters associated with all tags found in the given tags list.
        :param tags: A list of strings representing the tags associated with the
        task in question.
        :return: None
        """
        logger.debug(
            "Now incrementing tags: %s."
            % (tags,)
        )
        results = self.redis_helper.increment_tags(tags)
        for k, v in zip(tags, results):
            logger.debug(
                "Tag %s --> %s"
                % (k, v)
            )

    def __get_options_from_request(self, queue=None):
        """
        Get a dictionary containing all of the options found within self.request, for use in kicking
        off other tasks with similar requests.
        :param queue: The queue that the options should be associated with.
        :return: A dictionary containing all of the options found within self.request.
        """
        limit_hard, limit_soft = self.request.timelimit or (None, None)
        to_return = {
            "task_id": self.request.id,
            "link": self.request.callbacks,
            "link_error": self.request.errbacks,
            "group_id": self.request.group,
            "chord": self.request.chord,
            "soft_time_limit": limit_soft,
            "time_limit": limit_hard,
            "reply_to": self.request.reply_to,
            "headers": self.request.headers,
        }
        to_return.update(
            {'queue': queue} if queue else (self.request.delivery_info or {})
        )
        return to_return

    def __get_tags_from_task_kwargs(self, task_kwargs):
        """
        Get a list of strings representing the tags that should be associated with a task's invocation via
        apply_async from the given keyword arguments that were supplied to the task signature.
        :param task_kwargs: The keyword arguments supplied to the task signature.
        :return: A list of strings representing the tags that should be associated with a task's invocation via
        apply_async from the given keyword arguments that were supplied to the task signature.
        """
        to_return = []
        if "order_uuid" in task_kwargs:
            to_return.append(task_kwargs["order_uuid"])
        return to_return

    def __get_wait_on_tag_request(self, tag=None, check_interval=config.celery_retry_delay):
        """
        Get a Celery Request object that (1) is for a wait_for_tag task and (2) maintains references
        to all of the necessary metadata in self.request to ensure that chords and chains that self.request
        is involved in are maintained.
        :param tag: The tag to monitor.
        :param check_interval: The time in seconds to wait between checks of the tag value.
        :return: A Celery Request object.
        """
        kwargs = {
            "check_interval": check_interval,
            "tag": tag,
        }
        options = self.__get_options_from_request()
        signature = self._wait_for_tag_task.s(**kwargs)
        signature.options.update(options)
        return signature

    # Properties

    @property
    def id(self):
        """
        Get the ID for the task that is currently being executed.
        :return: The ID for the task that is currently being executed.
        """
        return self.request.id

    @property
    def redis_helper(self):
        """
        Get an instance of the RedisHelper singleton to use to query the Redis back-end.
        :return: An instance of the RedisHelper singleton to use to query the Redis back-end.
        """
        if self._redis_helper is None:
            self._redis_helper = RedisHelper.instance()
        return self._redis_helper

    @property
    def request_tags(self):
        """
        Get the tags associated with self.request.
        :return: The tags associated with self.request.
        """
        if self.request.headers is not None:
            return self.request.headers.get("tags", [])
        else:
            return []

    @property
    def start_time(self):
        """
        Get the time at which this task started. Note that this relies on the task_prerun_handler
        signal hook in app.py.
        :return: the time at which this task started. Note that this relies on the
        task_prerun_handler signal hook in app.py.
        """
        if self._start_time is None:
            logger.warning(
                "Start time not set! Task was %s (ID %s)."
                % (self.name, self.request.id)
            )
        return self._start_time

    @property
    def task_args(self):
        """
        Get the list of positional arguments supplied to the task's call method.
        :return: the list of positional arguments supplied to the task's call method.
        """
        return self._task_args

    @property
    def task_kwargs(self):
        """
        Get a dictionary containing the keyword arguments supplied to the task's call method.
        :return: a dictionary containing the keyword arguments supplied to the task's call method.
        """
        return self._task_kwargs

    # Representation and Comparison

    def __call__(self, *args, **kwargs):
        """
        Wrap the call to this task so that keyword and position arguments are stored within the class.
        :param args: Positional arguments for the called task.
        :param kwargs: Keyword arguments for the called task.
        :return: The result of the call.
        """
        self._task_args = args
        self._task_kwargs = kwargs
        return super(WebSightBaseTask, self).__call__(*args, **kwargs)

    def __repr__(self):
        return "<%s>" % (self.__class__.__name__,)


class DatabaseTask(WebSightBaseTask):
    """
    A base Celery Task class that has access to a SQLAlchemy session.
    """

    # Class Members

    abstract = True
    _commit_count = None
    _db_session = None
    _execution_count = None
    _flush_count = None
    _random_unique = None
    _rollback_count = None

    # Instantiation

    # Static Methods

    # Class Methods

    # Public Methods

    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        """
        Ensures that any database session opened by the Task is closed.
        :param status: Current task state.
        :param retval: Task return value/exception.
        :param task_id: Unique id of the task.
        :param args: Original arguments for the task that returned.
        :param kwargs: Original keyword arguments for the task that returned.
        :param einfo: ExceptionInfo instance, containing the traceback (if any).
        :return: None
        """
        super(DatabaseTask, self).after_return(status, retval, task_id, args, kwargs, einfo)

    def clean_up(self):
        """
        Clean up this DatabaseTask by closing and removing the database session.
        :return: None
        """
        super(DatabaseTask, self).clean_up()
        self.commit_session()
        self.__clear_db_connection()

    def commit_session(self):
        """
        Commit the current database session.
        :return: None
        """
        if self._commit_count is None:
            self._commit_count = 0
        self.db_session.commit()
        self._commit_count += 1

    def execute_session(self, to_execute):
        """
        Execute the given query and return the SQLAlchemy response.
        :param to_execute: The query to execute.
        :return: A SQLAlchemy result mapper.
        """
        if self._execution_count is None:
            self._execution_count = 0
        to_return = self.db_session.execute(to_execute)
        self._execution_count += 1
        return to_return

    def flush_session(self):
        """
        Flush the current database session.
        :return: None
        """
        if self._flush_count is None:
            self._flush_count = 0
        self.db_session.flush()
        self._flush_count += 1

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """
        Rolls back any pending database commits upon failure.
        :param exc: The exception raised by the task.
        :param task_id: Unique id of the failed task.
        :param args: Original arguments for the task that failed.
        :param kwargs: Original keyword arguments for the task that failed.
        :param einfo: ExceptionInfo instance, containing the traceback.
        :return: None
        """
        if self._db_session is not None:
            self._db_session.rollback()
        super(DatabaseTask, self).on_failure(exc, task_id, args, kwargs, einfo)

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        """
        Ensures that database connections are closed in the event that a retry is fired.
        :param exc: The exception raised by the task.
        :param task_id: Unique id of the failed task.
        :param args: Original arguments for the task that failed.
        :param kwargs: Original keyword arguments for the task that failed.
        :param einfo: ExceptionInfo instance, containing the traceback.
        :return: None
        """
        super(DatabaseTask, self).on_retry(exc, task_id, args, kwargs, einfo)

    def rollback_session(self):
        """
        Rollback the current database session.
        :return: None
        """
        if self._rollback_count is None:
            self._rollback_count = 0
        self.db_session.rollback()
        self._rollback_count += 1

    # Protected Methods

    # Private Methods

    def __clear_db_connection(self):
        """
        Clear the database connection if one currently exists.
        :return: None
        """
        if self._db_session is not None:
            self._db_session.close()
            self._db_session = None

    # Properties

    @property
    def db_session(self):
        """
        Get a SQLAlchemy session to use to query a database.
        :return: A SQLAlchemy session to use to query a database.
        """
        if self._db_session is None:
            self._db_session = get_sa_session()
        return self._db_session

    # Representation and Comparison


class ScanTask(DatabaseTask):
    """
    This is a base task type for all tasks that are invoked as the result of a scan.
    """

    abstract = True

    @property
    def order(self):
        """
        Get the order that this task is associated with.
        :return: the order that this task is associated with.
        """
        if self.order_uuid:
            return Order.by_uuid(uuid=self.order_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def order_uuid(self):
        """
        Get the UUID of the order that this task is associated with.
        :return: The UUID of the order that this task is associated with.
        """
        return self.task_kwargs.get("order_uuid", None)

    @property
    def organization(self):
        """
        Get the organization that this scanning task is associated with.
        :return: the organization that this scanning task is associated with.
        """
        return self.order.organization if self.order is not None else None

    @property
    def org_uuid(self):
        """
        Get the UUID of the organization that this task is associated with.
        :return: the UUID of the organization that this task is associated with.
        """
        return str(self.order.organization.uuid) if self.order is not None else None

    @property
    def scan_config(self):
        """
        Get the scanning configuration associated with the referenced order.
        :return: the scanning configuration associated with the referenced order.
        """
        order = self.order
        if order:
            return order.scan_config[0]
        else:
            return None


class DomainNameTask(ScanTask):
    """
    This is a base task type for all tasks that are intended to investigate a domain name.
    """

    abstract = True

    @property
    def domain(self):
        """
        Get the DomainName object that this task is associated with.
        :return: the DomainName object that this task is associated with.
        """
        if self.domain_uuid:
            return DomainName.by_uuid(uuid=self.domain_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def domain_scan(self):
        """
        Get the DomainNameScan object that this task is associated with.
        :return: the DomainNameScan object that this task is associated with.
        """
        if self.domain_scan_uuid:
            return DomainNameScan.by_uuid(uuid=self.domain_scan_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def domain_scan_uuid(self):
        """
        Get the UUID of the domain name scan that this task is associated with.
        :return: the UUID of the domain name scan that this task is associated with.
        """
        return self.task_kwargs.get("domain_scan_uuid", None)

    @property
    def domain_uuid(self):
        """
        Get the UUID of the domain name that this task is associated with.
        :return: the UUID of the domain name that this task is associated with.
        """
        return self.task_kwargs.get("domain_uuid", None)

    @property
    def inspector(self):
        """
        Get a domain name inspector that is configured to investigate the associated domain
        name.
        :return: A domain name inspector that is configured to investigate the associated domain
        name.
        """
        from lib.inspection import DomainInspector
        return DomainInspector(self.domain.name)


class NetworkTask(ScanTask):
    """
    This is a base task type for all tasks that are intended to investigate a network.
    """

    abstract = True

    @property
    def network(self):
        """
        Get the network that this task is associated with.
        :return: The network that this task is associated with.
        """
        if self.network_uuid:
            return Network.by_uuid(uuid=self.network_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def network_scan(self):
        """
        Get the NetworkScan that this task is associated with.
        :return: the NetworkScan that this task is associated with.
        """
        if self.network_scan_uuid:
            return OrganizationNetworkScan.by_uuid(uuid=self.network_scan_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def network_scan_uuid(self):
        """
        Get the UUID of the network scan that this task is associated with.
        :return: the UUID of the network scan that this task is associated with.
        """
        return self.task_kwargs.get("network_scan_uuid", None)

    @property
    def network_uuid(self):
        """
        Get the UUID of the network that this task is associated with.
        :return: the UUID of the network that this task is associated with.
        """
        return self.task_kwargs.get("network_uuid", None)


class ServiceTask(ScanTask):
    """
    This is a base task type for all tasks that are intended to investigate a network service.
    """

    abstract = True

    def get_endpoint_information(self, service_uuid):
        """
        Get a tuple containing the IP address, port, and protocol associated with the remote service.
        :param service_uuid: The UUID of the service to retrieve information about.
        :return: A tuple containing (1) the IP address, (2) the port, and (3) the protocol associated
        with the given service.
        """
        return get_endpoint_information_for_org_network_service(
            service_uuid=service_uuid,
            db_session=self.db_session,
        )


class WebServiceTask(ScanTask):
    """
    This is a base task type for all tasks that are intended to investigate a web service.
    """

    abstract = True

    @property
    def inspector(self):
        """
        Get a web service inspector that this task should use to investigate the referenced web
        service.
        :return: A web service inspector that this task should use to investigate the referenced web
        service.
        """
        from lib.inspection import WebServiceInspector
        return WebServiceInspector(
            ip_address=self.web_service.ip_address,
            port=self.web_service.port,
            hostname=self.web_service.host_name,
            use_ssl=self.web_service.ssl_enabled,
        )

    @property
    def web_service(self):
        """
        Get the web service that this task is related to.
        :return: The web service that this task is related to.
        """
        if self.web_service_uuid:
            return WebService.by_uuid(uuid=self.web_service_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def web_service_scan(self):
        """
        Get the web service scan that this task is related to.
        :return: The web service scan that this task is related to.
        """
        if self.web_service_scan_uuid:
            return WebServiceScan.by_uuid(uuid=self.web_service_scan_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def web_service_scan_uuid(self):
        """
        Get the UUID of the web service scan that this task is related to.
        :return: The UUID of the web service scan that this task is related to.
        """
        return self.task_kwargs.get("web_service_scan_uuid", None)

    @property
    def web_service_url(self):
        """
        Get a URL wrapper object that wraps this web service's URL.
        :return: A URL wrapper object that wraps this web service's URL.
        """
        return UrlWrapper.from_endpoint(
            hostname=self.web_service.host_name,
            port=self.web_service.port,
            use_ssl=self.web_service.ssl_enabled,
            path="/",
        )

    @property
    def web_service_uuid(self):
        """
        Get the UUID of the web service that this task is related to.
        :return: The UUID of the web service that this task is related to.
        """
        return self.task_kwargs.get("web_service_uuid", None)


class IpAddressTask(ScanTask):
    """
    This is a base task type for all tasks that are intended to investigate an IP address.
    """

    abstract = True

    @property
    def inspector(self):
        """
        Get the IP address inspector that this task should use to investigate the referenced IP
        address.
        :return: The IP address inspector that this task should use to investigate the referenced IP
        address.
        """
        from lib.inspection import IpAddressInspector
        return IpAddressInspector(ip_address=self.ip_address.address, address_type=self.ip_address.address_type)

    @property
    def ip_address(self):
        """
        Get the IP address that this task is intended to analyze.
        :return: the IP address that this task is intended to analyze.
        """
        if self.ip_address_uuid:
            return IpAddress.by_uuid(uuid=self.ip_address_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def ip_address_scan(self):
        """
        Get the IP address scan that this task is related to.
        :return: the IP address scan that this task is related to.
        """
        if self.ip_address_scan_uuid:
            return IpAddressScan.by_uuid(uuid=self.ip_address_scan_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def ip_address_scan_uuid(self):
        """
        Get the UUID of the IP address scan that this task is related to.
        :return: the UUID of the IP address scan that this task is related to.
        """
        return self.task_kwargs.get("ip_address_scan_uuid", None)

    @property
    def ip_address_uuid(self):
        """
        Get the UUID of the IP address that this task is intended to analyze.
        :return: the UUID of the IP address that this task is intended to analyze.
        """
        return self.task_kwargs.get("ip_address_uuid", None)


class NetworkServiceTask(ScanTask):
    """
    This is a base task type for all tasks that are intended to investigate a network service.
    """

    abstract = True

    def get_endpoint_information(self):
        """
        Get a tuple containing the IP address, port, and protocol associated with the remote service.
        :return: A tuple containing (1) the IP address, (2) the port, and (3) the protocol associated
        with the given service.
        """
        return get_endpoint_information_for_org_network_service(
            service_uuid=self.network_service_uuid,
            db_session=self.db_session,
        )

    @property
    def inspector(self):
        """
        Get the port inspector that this task should use to investigate the referenced network service.
        :return: The port inspector that this task should use to investigate the referenced network service.
        """
        from lib.inspection import PortInspector
        return PortInspector(
            address=self.network_service.ip_address.address,
            port=self.network_service.port,
            protocol=self.network_service.protocol,
        )

    @property
    def is_tcp_service(self):
        """
        Get whether or not this network service is a TCP service.
        :return: whether or not this network service is a TCP service.
        """
        return self.network_service.protocol.lower() == "tcp"

    @property
    def is_udp_service(self):
        """
        Get whether or not this network service is a UDP service.
        :return: whether or not this network service is a UDP service.
        """
        return self.network_service.protocol.lower() == "udp"

    @property
    def network_service(self):
        """
        Get the network service that this task is related to.
        :return: The network service that this task is related to.
        """
        if self.network_service_uuid:
            return NetworkService.by_uuid(uuid=self.network_service_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def network_service_scan(self):
        """
        Get the network service scan that this task is related to.
        :return: The network service scan that this task is related to.
        """
        if self.network_service_scan_uuid:
            return NetworkServiceScan.by_uuid(uuid=self.network_service_scan_uuid, db_session=self.db_session)
        else:
            return None

    @property
    def network_service_scan_uuid(self):
        """
        Get the UUID of the network service scan that this task is related to.
        :return: The UUID of the network service scan that this task is related to.
        """
        return self.task_kwargs.get("network_service_scan_uuid", None)

    @property
    def network_service_uuid(self):
        """
        Get the UUID of the network service that this task is related to.
        :return: The UUID of the network service that this task is related to.
        """
        return self.task_kwargs.get("network_service_uuid", None)


@websight_app.task(bind=True, base=DatabaseTask, max_retries=None)
def wait_for_tag(self, tag=None, check_interval=config.celery_retry_delay):
    """
    This task continues to inspect the state of the specified tag (in a Redis server). Once the
    value of the tag is 0, the task finishes. Otherwise it retries indefinitely.
    :param tag: The tag to watch.
    :param check_interval: The interval (in seconds) to wait between checking the tag.
    :return: None
    """
    logger.debug(
        "Now checking on tag %s."
        % (tag,)
    )
    tag_value = int(self.redis_helper.get_tag(tag))
    if tag_value > 0:
        logger.debug(
            "Tag value (%s) was greater than zero (%s). Retrying in %s seconds."
            % (tag, tag_value, check_interval)
        )
        raise self.retry(countdown=check_interval)
    else:
        logger.debug("Tag value was zero! Concluding task.")


WebSightBaseTask._wait_for_tag_task = wait_for_tag
