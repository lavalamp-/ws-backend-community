# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import Celery
from celery.signals import celeryd_after_setup, worker_process_init, worker_ready, worker_shutdown, task_prerun
from celery.utils.log import get_task_logger
import requests

from lib import ConfigManager, DatetimeHelper

config = ConfigManager.instance()
logger = get_task_logger(__name__)


websight_app = Celery(
    config.celery_app_name,
    broker=config.celery_broker_url,
    include=[
        "tasknode.tasks",
    ],
)


websight_app.conf.update(
    CELERY_ACCEPT_CONTENT=[config.celery_task_serializer],
    CELERY_DISABLE_RATE_LIMITS=True,
    CELERY_ENABLE_UTC=config.celery_enable_utc,
    CELERY_EVENT_SERIALIZER=config.celery_task_serializer,
    CELERY_MESSAGE_COMPRESSION=config.celery_message_compression,
    CELERY_REDIRECT_STDOUTS=config.celery_redirect_stdouts,
    CELERY_RESULT_BACKEND=config.celery_results_backend,
    CELERY_RESULT_PERSISTENT=True,
    CELERY_RESULT_SERIALIZER=config.celery_task_serializer,
    CELERY_TASK_SERIALIZER=config.celery_task_serializer,
    CELERY_TRACK_STARTED=config.celery_track_started,
    CELERYD_MAX_TASKS_PER_CHILD=config.celery_max_tasks_per_child,
    CELERYD_PREFETCH_MULTIPLIER=config.celeryd_prefetch_multiplier,
    # CELERYD_POOL=config.celery_worker_pool,
    CELERYD_HIJACK_ROOT_LOGGER=False,
)


@celeryd_after_setup.connect
def prepare_tasknode(sender=None, instance=None, **kwargs):
    """
    Celeryd hook
    """
    logger.debug("celeryd_after_setup hook")
    requests.packages.urllib3.disable_warnings()


@worker_process_init.connect
def prep_worker_process(signal=None, sender=None, **named):
    """
    Celeryd hook
    """
    logger.debug("worker_process_init hook")


@worker_ready.connect
def update_host_start_up(signal=None, sender=None, **named):
    """
    Celeryd hook
    """
    logger.debug("worker_ready hook")


@worker_shutdown.connect
def update_host_shutdown(signal=None, sender=None, **named):
    """
    Celeryd hook
    """
    logger.debug("worker_shutdown hook")


@task_prerun.connect
def task_prerun_handler(signal, sender, task_id, task, *args, **kwargs):
    """
    Handle any sort of preparations for a task prior to it running.
    :param signal: The signal that was processed.
    :param sender: The entity that sent the task.
    :param task_id: The task's ID.
    :param task: The task itself.
    :param args: Positional arguments for the task.
    :param kwargs: Keyword arguments for the task.
    :return: None
    """
    from .tasks.base import DatabaseTask
    task._start_time = DatetimeHelper.now()
    if isinstance(task, DatabaseTask):
        if task._db_session is not None:
            logger.debug(
                "Task %s (%s) has a non-None db_session. Resetting now."
                % (task.name, task.id)
            )
            task._db_session = None


@websight_app.on_after_configure.connect
def setup_periodic_tasks(sender, **kwargs):
    """
    Handle setting up all of the periodic tasks for the scheduler.
    :param sender:
    :param kwargs:
    :return:
    """
