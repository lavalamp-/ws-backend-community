# -*- coding: utf-8 -*-
from __future__ import absolute_import

import time

from celery import chain, group
from celery.utils.log import get_task_logger

from lib.sqlalchemy import get_or_create_web_service_from_network_service, create_new_web_service_scan, \
    update_web_service_scan_completed as update_web_service_scan_completed_op, DefaultFlag
from ......app import websight_app
from .....base import ServiceTask, WebServiceTask, DatabaseTask, NetworkServiceTask
from .virtualhost import discover_virtual_hosts_for_web_service
from wselasticsearch.ops import get_supported_ssl_version_for_service, update_web_service_scan_latest, \
    update_web_service_scan_not_latest, get_virtual_hosts_from_network_service_scan
from .crawling import crawl_web_service
from .imaging import screenshot_web_service
from .analysis import create_report_for_web_service_scan
from .fingerprinting import enumerate_user_agent_fingerprints_for_web_service
from wselasticsearch.ops import get_all_domains_for_ip_address
from lib.sqlalchemy.ops import get_latest_web_service_scan_uuid, check_web_service_scanning_status, \
    update_web_service_scanning_status as update_web_service_scanning_status_op, get_all_web_flags_for_organization
from lib import ConfigManager
from wselasticsearch.flags import DataFlagger

logger = get_task_logger(__name__)
config = ConfigManager.instance()


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def inspect_http_service(
        self,
        org_uuid=None,
        network_service_scan_uuid=None,
        network_service_uuid=None,
        order_uuid=None,
):
    """
    Inspect the HTTP service running on the given network service on behalf of the given
    organization and network service scan.
    :param org_uuid: The UUID of the organization to inspect the HTTP service on behalf of.
    :param network_service_scan_uuid: The UUID of the network service scan.
    :param network_service_uuid: The UUID of the network service.
    :return: None
    """
    logger.info(
        "Now inspecting HTTP service residing on network service %s. Organization is %s."
        % (network_service_uuid, org_uuid)
    )
    scan_config = self.order.scan_config
    if scan_config.web_app_enum_vhosts:
        task_sigs = []
        task_kwargs = {
            "org_uuid": org_uuid,
            "network_service_scan_uuid": network_service_scan_uuid,
            "network_service_uuid": network_service_uuid,
            "use_ssl": False,
            "order_uuid": order_uuid,
        }
        task_sigs.append(discover_virtual_hosts_for_web_service.si(**task_kwargs))
        task_sigs.append(inspect_virtual_hosts_for_network_service.si(**task_kwargs))
        logger.info(
            "Now kicking off %s tasks to inspect HTTP service at %s. Organization is %s."
            % (len(task_sigs), network_service_uuid, org_uuid)
        )
        canvas_sig = chain(task_sigs)
        self.finish_after(signature=canvas_sig)
    else:
        populate_and_scan_web_services_from_network_service_scan.si(
            org_uuid=org_uuid,
            network_service_scan_uuid=network_service_scan_uuid,
            network_service_uuid=network_service_uuid,
            use_ssl=False,
            order_uuid=order_uuid,
        ).apply_async()


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def inspect_https_service(
        self,
        org_uuid=None,
        network_service_scan_uuid=None,
        network_service_uuid=None,
        order_uuid=None,
):
    """
    Inspect the HTTPS service running on the given network service on behalf of the given
    organization and network service scan.
    :param org_uuid: The UUID of the organization to inspect the HTTPS service on behalf of.
    :param network_service_scan_uuid: The UUID of the network service scan.
    :param network_service_uuid: The UUID of the network service.
    :return: None
    """
    logger.info(
        "Now inspecting HTTPS service residing on network service %s. Organization is %s."
        % (network_service_uuid, org_uuid)
    )
    scan_config = self.order.scan_config
    if scan_config.web_app_enum_vhosts:
        task_sigs = []
        task_kwargs = {
            "org_uuid": org_uuid,
            "network_service_scan_uuid": network_service_scan_uuid,
            "network_service_uuid": network_service_uuid,
            "use_ssl": True,
            "order_uuid": order_uuid,
        }
        task_sigs.append(discover_virtual_hosts_for_web_service.si(**task_kwargs))
        task_sigs.append(inspect_virtual_hosts_for_network_service.si(**task_kwargs))
        logger.info(
            "Now kicking off %s tasks to inspect HTTPS service at %s. Organization is %s."
            % (len(task_sigs), network_service_uuid, org_uuid)
        )
        canvas_sig = chain(task_sigs)
        self.finish_after(signature=canvas_sig)
    else:
        populate_and_scan_web_services_from_network_service_scan.si(
            org_uuid=org_uuid,
            network_service_scan_uuid=network_service_scan_uuid,
            network_service_uuid=network_service_uuid,
            use_ssl=True,
        ).apply_async()


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def populate_and_scan_web_services_from_network_service_scan(
        self,
        org_uuid=None,
        network_service_scan_uuid=None,
        network_service_uuid=None,
        use_ssl=None,
        order_uuid=None,
):
    """
    Populate all of the relevant web services as found through the given network service scan
    and kick off scanning for all of the web services.
    :param org_uuid: The UUID of the organization to kick scans off for.
    :param network_service_scan_uuid: The UUID of the network service scan that invoked this task.
    :param network_service_uuid: The UUID of the network service that was scanned.
    :param use_ssl: Whether the web services created from this task should be marked as HTTPS or not.
    :return: None
    """
    logger.info(
        "Now populating and scanning web services for network service scan %s."
        % (network_service_scan_uuid,)
    )
    domain_names = get_all_domains_for_ip_address(
        org_uuid=org_uuid,
        ip_address=self.network_service.ip_address.address,
        filter_by_latest=True,
    )
    task_sigs = []
    for domain_name in domain_names:
        web_service = get_or_create_web_service_from_network_service(
            network_service_uuid=network_service_uuid,
            db_session=self.db_session,
            host_name=domain_name,
            ip_address=self.network_service.ip_address.address,
            port=self.network_service.port,
            use_ssl=use_ssl,
        )
        task_sigs.append(scan_web_service.si(
            org_uuid=org_uuid,
            web_service_uuid=web_service.uuid,
            order_uuid=order_uuid,
        ))
    if len(task_sigs) == 0:
        logger.info(
            "No tasks created for scanning web services for network service scan %s."
            % (network_service_scan_uuid,)
        )
    group(task_sigs).apply_async()


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def scan_web_service(
        self,
        org_uuid=None,
        web_service_uuid=None,
        order_uuid=None,
):
    """
    Scan the given web service and collect all data relevant to the Web Sight platform for the endpoint.
    :param org_uuid: The UUID of the organization that owns the web service.
    :param web_service_uuid: The UUID of the web service.
    :return: None
    """
    logger.info(
        "Now scanning web service %s for organization %s."
        % (web_service_uuid, org_uuid)
    )
    should_scan = check_web_service_scanning_status(
        db_session=self.db_session,
        web_service_uuid=web_service_uuid,
        update_status=True,
    )
    if not should_scan:
        logger.info(
            "Should not scan web service %s. Exiting."
            % (web_service_uuid,)
        )
        return
    web_service_scan = create_new_web_service_scan(
        web_service_uuid=web_service_uuid,
        db_session=self.db_session,
    )
    self.db_session.add(web_service_scan)
    self.db_session.commit()
    task_sigs = []
    task_kwargs = {
        "org_uuid": org_uuid,
        "web_service_uuid": web_service_uuid,
        "web_service_scan_uuid": web_service_scan.uuid,
        "order_uuid": order_uuid,
    }
    scan_config = self.order.scan_config
    if scan_config.web_app_enum_user_agents:
        task_sigs.append(enumerate_user_agent_fingerprints_for_web_service.si(**task_kwargs))
    if scan_config.web_app_do_crawling:
        task_sigs.append(crawl_web_service.si(**task_kwargs))
    else:
        task_sigs.append(retrieve_landing_resource_for_web_service.si(**task_kwargs))
    if scan_config.web_app_take_screenshot:
        task_sigs.append(screenshot_web_service.si(**task_kwargs))
    task_sigs.append(create_report_for_web_service_scan.si(**task_kwargs))
    task_sigs.append(apply_flags_to_web_service_scan.si(**task_kwargs))
    task_sigs.append(update_web_service_scan_elasticsearch.si(**task_kwargs))
    task_sigs.append(update_web_service_scan_completed.si(**task_kwargs))
    scanning_status_sig = update_web_service_scanning_status.si(
        web_service_uuid=web_service_uuid,
        scanning_status=False,
        order_uuid=order_uuid,
    )
    task_sigs.append(scanning_status_sig)
    logger.info(
        "Now kicking off all necessary tasks to scan web service %s."
        % (web_service_uuid,)
    )
    canvas_sig = chain(task_sigs)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def retrieve_landing_resource_for_web_service(
        self,
        org_uuid=None,
        web_service_uuid=None,
        web_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Retrieve the resource at the landing URL for the given web service.
    :param org_uuid: The UUID of the organization to crawl the web service on behalf of.
    :param web_service_uuid: The UUID of the web service to crawl.
    :param web_service_scan_uuid: The UUID of the scan that this crawling session is part of.
    :return: None
    """
    logger.info(
        "Now retrieving the landing resource for web service %s and organization %s."
        % (web_service_uuid, org_uuid)
    )
    response = self.inspector.get(path="/")
    es_model = response.get_web_resource_model(web_service_scan=self.web_service_scan, site_url=self.web_service_url)
    es_model.save(org_uuid)
    logger.info(
        "Retrieved landing resource for web service %s and organization %s."
        % (web_service_uuid, org_uuid)
    )


#USED
@websight_app.task(bind=True, base=NetworkServiceTask)
def inspect_virtual_hosts_for_network_service(
        self,
        org_uuid=None,
        network_service_scan_uuid=None,
        network_service_uuid=None,
        use_ssl=None,
        order_uuid=None,
):
    """
    Perform inspection for all of the virtual hosts associated with the given network service as discovered
    during the given network service scan.
    :param org_uuid: The UUID of the organization to inspect virtual hosts on behalf of.
    :param network_service_scan_uuid: The UUID of the network service scan that this task is being
    invoked on behalf of.
    :param network_service_uuid: The UUID of the network service where the virtual hosts reside.
    :param use_ssl: Whether or not to interact with the remote service over SSL.
    :return: None
    """
    logger.info(
        "Now beginning inspection of virtual hosts found at network service %s for organization %s."
        % (network_service_uuid, org_uuid)
    )
    ip_address, port, protocol = self.get_endpoint_information()
    virtual_host_domains = get_virtual_hosts_from_network_service_scan(
        scan_uuid=network_service_scan_uuid,
        org_uuid=org_uuid,
    )
    logger.info(
        "A total of %s virtual hosts were found for network service %s."
        % (len(virtual_host_domains), network_service_uuid)
    )
    task_sigs = []
    scan_config = self.order.scan_config
    #TODO refactor this into invocations of scan_web_service
    for domain in virtual_host_domains:
        web_service = get_or_create_web_service_from_network_service(
            network_service_uuid=network_service_uuid,
            db_session=self.db_session,
            host_name=domain,
            ip_address=ip_address,
            port=port,
            use_ssl=use_ssl,
        )
        web_service_scan = create_new_web_service_scan(
            web_service_uuid=web_service.uuid,
            db_session=self.db_session,
        )
        self.commit_session()
        web_scan_task_sigs = []
        task_kwargs = {
            "org_uuid": org_uuid,
            "web_service_scan_uuid": web_service_scan.uuid,
            "web_service_uuid": web_service.uuid,
            "order_uuid": order_uuid,
        }
        if scan_config.web_app_enum_user_agents:
            web_scan_task_sigs.append(enumerate_user_agent_fingerprints_for_web_service.si(**task_kwargs))
        if scan_config.web_app_do_crawling:
            web_scan_task_sigs.append(crawl_web_service.si(**task_kwargs))
        else:
            web_scan_task_sigs.append(retrieve_landing_resource_for_web_service.si(**task_kwargs))
        if scan_config.web_app_take_screenshot:
            web_scan_task_sigs.append(screenshot_web_service.si(**task_kwargs))
        web_scan_task_sigs.append(create_report_for_web_service_scan.si(**task_kwargs))
        web_scan_task_sigs.append(apply_flags_to_web_service_scan.si(**task_kwargs))
        web_scan_task_sigs.append(update_web_service_scan_elasticsearch.si(**task_kwargs))
        web_scan_task_sigs.append(update_web_service_scan_completed.si(**task_kwargs))
        scanning_status_sig = update_web_service_scanning_status.si(
            web_service_uuid=web_service.uuid,
            scanning_status=False,
            order_uuid=order_uuid,
        )
        web_scan_task_sigs.append(scanning_status_sig)
        task_sigs.append(chain(web_scan_task_sigs))
    logger.info(
        "Now kicking off scans to analyze %s virtual hosts associated with network service %s."
        % (len(task_sigs), network_service_uuid)
    )
    canvas_sig = group(task_sigs)
    canvas_sig.apply_async()


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def update_web_service_scan_elasticsearch(
        self,
        org_uuid=None,
        web_service_scan_uuid=None,
        web_service_uuid=None,
        order_uuid=None,
):
    """
    Update Elasticsearch so that all of the Elasticsearch documents collected by this web service scan
    are marked as being part of the most recent scan, and update all of the documents collected by the
    previous web service scan so that they are no longer marked as most recent.
    :param org_uuid: The UUID of the organization to update Elasticsearch on behalf of.
    :param web_service_uuid: The UUID of web service being scanned..
    :param web_service_scan_uuid: The UUID of the web service scan to update Elasticsearch based on.
    :return: None
    """
    logger.info(
        "Now updating web service %s to show that scan %s is most recent in Elasticsearch. Organization is %s."
        % (web_service_uuid, web_service_scan_uuid, org_uuid)
    )
    self.wait_for_es(duration=5)
    last_scan_uuid = get_latest_web_service_scan_uuid(db_session=self.db_session, web_service_uuid=web_service_uuid)
    update_web_service_scan_latest(org_uuid=org_uuid, scan_uuid=web_service_scan_uuid)
    if last_scan_uuid is not None:
        self.wait_for_es(duration=5)
        update_web_service_scan_not_latest(scan_uuid=last_scan_uuid, org_uuid=org_uuid)


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def update_web_service_scan_completed(
        self,
        org_uuid=None,
        web_service_scan_uuid=None,
        web_service_uuid=None,
        order_uuid=None,
):
    """
    Update the referenced web service scan and mark it as having been completed.
    :param org_uuid: The UUID of the organization that owns the scan.
    :param web_service_scan_uuid: The UUID of the web service scan to update.
    :param web_service_uuid: The UUID of the web service that was scanned.
    :return: None
    """
    logger.info(
        "Now updating web service scan %s as completed."
        % (web_service_uuid,)
    )
    update_web_service_scan_completed_op(scan_uuid=web_service_scan_uuid, db_session=self.db_session)
    logger.info(
        "Web service scan %s marked as completed."
        % (web_service_scan_uuid,)
    )


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def update_web_service_scanning_status(
        self,
        org_uuid=None,
        web_service_uuid=None,
        scanning_status=None,
        order_uuid=None,
):
    """
    Update the current scanning status of the given web service.
    :param org_uuid: The UUID of the organization that owns the web service.
    :param web_service_uuid: The UUID of the web service to update.
    :param scanning_status: The value to set the web application's scanning status to.
    :return: None
    """
    logger.info(
        "Now updating scanning status of web service %s to %s."
        % (web_service_uuid, scanning_status)
    )
    update_web_service_scanning_status_op(
        status=scanning_status,
        web_service_uuid=web_service_uuid,
        db_session=self.db_session,
    )
    self.db_session.commit()


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def apply_flags_to_web_service_scan(
        self,
        org_uuid=None,
        web_service_uuid=None,
        web_service_scan_uuid=None,
        order_uuid=None,
):
    """
    Apply all of the relevant flags to the data collected during the given web service scan.
    :param org_uuid: The UUID of the organization that flags are being applied for.
    :param web_service_uuid: The UUID of the web service that was scanned.
    :param web_service_scan_uuid: The UUID of the web service scan to update data for.
    :return: None
    """
    logger.info(
        "Now applying flags to web service scan %s."
        % (web_service_scan_uuid,)
    )
    flags = get_all_web_flags_for_organization(db_session=self.db_session, org_uuid=org_uuid)
    if len(flags) == 0:
        logger.info(
            "No web flags found for organization %s."
            % (org_uuid,)
        )
        return
    task_sigs = []
    for flag in flags:
        flag_type = "default" if isinstance(flag, DefaultFlag) else "organization"
        task_sigs.append(apply_flag_to_web_service_scan.si(
            org_uuid=org_uuid,
            web_service_uuid=web_service_uuid,
            web_service_scan_uuid=web_service_scan_uuid,
            flag_uuid=flag.uuid,
            flag_type=flag_type,
            order_uuid=order_uuid,
        ))
    canvas_sig = chain(task_sigs)
    self.finish_after(signature=canvas_sig)


#USED
@websight_app.task(bind=True, base=WebServiceTask)
def apply_flag_to_web_service_scan(
        self,
        org_uuid=None,
        web_service_uuid=None,
        web_service_scan_uuid=None,
        flag_uuid=None,
        flag_type=None,
        order_uuid=None,
):
    """
    Apply the given flag to the data collected during the given web service scan.
    :param org_uuid: The UUID of the organization that flags are being applied for.
    :param web_service_uuid: The UUID of the web service that was scanned.
    :param web_service_scan_uuid: The UUID of the web service scan to update data for.
    :param flag_uuid: The UUID of the flag to apply.
    :param flag_type: The type of flag to apply.
    :return: None
    """
    logger.info(
        "Now applying flag %s to web service scan %s."
        % (flag_uuid, web_service_scan_uuid)
    )
    flagger = DataFlagger.from_flag_uuid(flag_uuid=flag_uuid, flag_type=flag_type, db_session=self.db_session)
    flagger.filter_by_web_service_scan(web_service_scan_uuid)
    self.wait_for_es()
    flagger.apply_flag_to_organization(org_uuid=org_uuid)
    logger.info(
        "Flag %s successfully applied to web service scan %s."
        % (flag_uuid, web_service_scan_uuid)
    )
