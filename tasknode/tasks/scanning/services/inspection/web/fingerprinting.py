# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group
from celery.utils.log import get_task_logger

from lib.inspection import WebServiceInspector
from lib.parsing.wrappers.mime.base import BaseMarkupWrapper
from ......app import websight_app
from .....base import WebServiceTask
from lib.parsing import UserAgentCsvFileWrapper
from lib.sqlalchemy import get_endpoint_information_for_web_service
from wselasticsearch.models import UserAgentFingerprintModel

logger = get_task_logger(__name__)


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def enumerate_user_agent_fingerprints_for_web_service(
        self,
        org_uuid=None,
        web_service_uuid=None,
        web_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Perform fingerprinting for the given web service to determine if different user agents result in different
    responses being returned.
    :param org_uuid: The UUID of the organization to fingerprint the web service on behalf of.
    :param web_service_uuid: The UUID of the web service to gather fingerprints for.
    :param web_service_scan_uuid: The UUID of the web service scan to perform fingerprinting for.
    :return: None
    """
    logger.info(
        "Now enumerating user agent fingerprints for web service scan %s."
        % (web_service_scan_uuid,)
    )
    user_agents_file = UserAgentCsvFileWrapper.from_default_file()
    task_sigs = []
    for user_agent in user_agents_file.user_agents:
        task_sigs.append(get_user_agent_fingerprint_for_web_service.si(
            org_uuid=org_uuid,
            web_service_uuid=web_service_uuid,
            web_service_scan_uuid=web_service_scan_uuid,
            user_agent_type=user_agent.agent_type,
            user_agent_name=user_agent.agent_name,
            user_agent_string=user_agent.user_agent,
            order_uuid=order_uuid,
        ))
    canvas_sig = group(task_sigs)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def get_user_agent_fingerprint_for_web_service(
        self,
        org_uuid=None,
        web_service_uuid=None,
        web_service_scan_uuid=None,
        user_agent_type=None,
        user_agent_name=None,
        user_agent_string=None,
        order_uuid=None,
):
    """
    Get a user agent fingerprint from the given web service using the given user agent.
    :param org_uuid: The UUID of the organization to get the fingerprint for.
    :param web_service_uuid: The UUID of the web service to fingerprint.
    :param web_service_scan_uuid: The UUID of the web service scan to get the fingerprint for.
    :param user_agent_type: The type of user agent being tested.
    :param user_agent_name: A name for the user agent being tested.
    :param user_agent_string: A string containing the user agent to test with.
    :return: None
    """
    logger.info(
        "Now testing web service %s for user agent fingerprint %s (%s)."
        % (web_service_uuid, user_agent_name, user_agent_string)
    )
    response = self.inspector.get(user_agent=user_agent_string)
    if isinstance(response.response_content_wrapper, BaseMarkupWrapper):
        secondary_hash = response.response_content_wrapper.full_decomposition
    else:
        secondary_hash = response.response_content_hash
    user_agent_fingerprint = UserAgentFingerprintModel.from_database_model_uuid(
        uuid=web_service_scan_uuid,
        db_session=self.db_session,
        user_agent_type=user_agent_type,
        user_agent_name=user_agent_name,
        user_agent_string=user_agent_string,
        response_has_content=response.response_has_content,
        response_mime_type=response.response_mime_string,
        response_primary_hash=response.response_content_hash,
        response_secondary_hash=secondary_hash,
        response_status_code=response.response_status_code,
    )
    user_agent_fingerprint.save(org_uuid)
    logger.info(
        "Successfully gathered user agent fingerprint %s (%s) for web service %s."
        % (user_agent_name, user_agent_string, web_service_uuid)
    )
