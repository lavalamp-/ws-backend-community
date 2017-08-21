# -*- coding: utf-8 -*-
from __future__ import absolute_import

from celery import group, chain
from celery.utils.log import get_task_logger
from elasticsearch import ConnectionTimeout

from lib import ConversionHelper, FilesystemHelper
from lib.tools import ZmapRunner
from tasknode.app import websight_app
from tasknode.tasks.base import DatabaseTask, ScanTask, NetworkTask
from lib.sqlalchemy import get_enabled_network_ranges_for_organization, get_ports_to_scan_for_organization, \
    get_containing_network_uuid_for_organization, get_or_create_ip_address_from_org_network, \
    get_or_create_network_service_from_org_ip, create_network_scan_for_organization, update_network_scan_completed, \
    get_org_uuid_from_order, get_monitored_network_ranges_for_order, get_ports_to_scan_for_scan_config
from .services import scan_network_service
from .ip import scan_ip_address

logger = get_task_logger(__name__)


#TESTME
def create_zmap_whitelist_file_for_order(order_uuid=None, file_path=None, db_session=None):
    """
    Create a Zmap whitelist file for the given order at the given file path.
    :param order_uuid: The UUID of the order to create the whitelist file for.
    :param file_path: The local file path to write the file to.
    :param db_session: A SQLAlchemy session.
    :return: None
    """
    ranges = get_monitored_network_ranges_for_order(order_uuid=order_uuid, db_session=db_session)
    FilesystemHelper.write_to_file(file_path=file_path, data="\n".join(ranges))


#USED
@websight_app.task(bind=True, base=ScanTask)
def zmap_scan_order(self, order_uuid=None):
    """
    Perform Zmap scans for all necessary ports for the given order.
    :param order_uuid: The UUID of the order to scan.
    :return: None
    """
    port_tuples = get_ports_to_scan_for_scan_config(
        config_uuid=self.order.scan_config.uuid,
        db_session=self.db_session,
    )
    logger.info(
        "Now scanning order %s for %s total ports."
        % (order_uuid, len(port_tuples))
    )
    task_signatures = []
    scan_signatures = []
    network_scan = create_network_scan_for_organization(
        db_session=self.db_session,
        org_uuid=self.org_uuid,
    )
    self.commit_session()
    for port, protocol in port_tuples:
        scan_signatures.append(zmap_scan_order_for_port.si(
            port=port,
            protocol=protocol,
            order_uuid=order_uuid,
            network_scan_uuid=network_scan.uuid,
        ))
    task_signatures.append(group(scan_signatures))
    task_signatures.append(update_zmap_scan_completed.si(
        scan_uuid=network_scan.uuid,
        org_uuid=self.org_uuid,
        order_uuid=order_uuid,
    ))
    logger.info("Kicking off Zmap subtasks now.")
    canvas_sig = chain(task_signatures)
    canvas_sig.apply_async()


#USED
@websight_app.task(bind=True, base=NetworkTask)
def update_zmap_scan_completed(self, org_uuid=None, scan_uuid=None, order_uuid=None):
    """
    Update the ZmapScanModel Elasticsearch document with the given scan_uuid to indicate that
    scanning has completed.
    :param org_uuid: The UUID of the organization that was scanned.
    :param scan_uuid: The UUID of the ZmapScanModel to update.
    :return: None
    """
    logger.info(
        "Now updating ZmapScanModel %s to show that Zmap scanning has concluded for organization %s."
        % (scan_uuid, org_uuid)
    )
    update_network_scan_completed(scan_uuid=scan_uuid, db_session=self.db_session)
    logger.info(
        "ZmapScanModel %s updated to show Zmap scanning was completed."
        % (scan_uuid,)
    )


#USED
@websight_app.task(bind=True, base=NetworkTask)
def zmap_scan_order_for_port(
        self,
        port=None,
        protocol=None,
        order_uuid=None,
        network_scan_uuid=None,
):
    """
    Perform a Zmap scan for all networks associated with the given order for the given port and protocol.
    :param port: The port to scan for.
    :param protocol: The protocol to scan for.
    :param order_uuid: The UUID of the order to run the scan for.
    :param network_scan_uuid: The UUID of the network scan that this Zmap scan is a part of.
    :return: None
    """
    logger.info(
        "Now scanning Order %s for port %s (%s)."
        % (order_uuid, port, protocol)
    )
    whitelist_path = self.get_temporary_file_path()
    create_zmap_whitelist_file_for_order(
        order_uuid=order_uuid,
        db_session=self.db_session,
        file_path=whitelist_path,
    )
    output_path = self.get_temporary_file_path()
    scan_config = self.order.scan_config
    scanner = ZmapRunner.from_scan_config(scan_config)
    scanner.target_port = port
    scanner.set_scan_protocol(protocol)
    scanner.whitelist_file = whitelist_path
    scanner.output_file = output_path
    logger.info("Starting Zmap scan.")
    scanner.run()
    logger.info("Zmap scan completed.")
    scan_record = scanner.to_es_model(model_uuid=network_scan_uuid, db_session=self.db_session)
    try:
        scan_record.save(self.org_uuid)
        logger.info("Elasticsearch updated with scan record.")
    except ConnectionTimeout as e:
        logger.error(
            "Connection timeout thrown when attempting to index Zmap scan results: %s."
            % (e.message,)
        )
    if scan_config.network_inspect_live_hosts:
        results_parser = scanner.get_results_parser()
        task_signatures = []
        for live_ip in results_parser.get_live_ips():
            task_signatures.append(handle_live_zmap_service.si(
                port=port,
                protocol=protocol,
                ip_address=live_ip,
                org_uuid=self.org_uuid,
                network_scan_uuid=network_scan_uuid,
                order_uuid=order_uuid,
            ))
        canvas_sig = group(task_signatures)
        logger.info(
            "Now kicking off %s tasks to handle results of Zmap scan for order %s and port %s (%s)."
            % (len(task_signatures), order_uuid, port, protocol)
        )
        canvas_sig.apply_async()


#USED
@websight_app.task(bind=True, base=NetworkTask)
def handle_live_zmap_service(
        self,
        port=None,
        protocol=None,
        ip_address=None,
        org_uuid=None,
        network_scan_uuid=None,
        order_uuid=None,
):
    """
    Process the result of a live service found via a Zmap scan for initiation into the Web Sight monitoring
    system.
    :param port: The port that was found to be open.
    :param protocol: The protocol used to connect to the port.
    :param ip_address: The IP address where the port resides.
    :param org_uuid: The UUID of the organization.
    :param network_scan_uuid: The UUID of the scan.
    :return: None
    """
    logger.info(
        "Now handling live service Zmap result for port %s:%s (%s). Organization is %s, scan is %s."
        % (ip_address, port, protocol, org_uuid, network_scan_uuid)
    )
    network_uuid = get_containing_network_uuid_for_organization(
        org_uuid=org_uuid,
        input_ip_address=ip_address,
        db_session=self.db_session,
    )
    ip_address_model = get_or_create_ip_address_from_org_network(
        network_uuid=network_uuid,
        address=ip_address,
        address_type="ipv4",
        db_session=self.db_session,
    )
    network_service_model = get_or_create_network_service_from_org_ip(
        ip_uuid=ip_address_model.uuid,
        port=port,
        protocol=protocol,
        db_session=self.db_session,
        discovered_by="network scan",
    )
    task_signatures = []
    scan_config = self.order.scan_config
    if scan_config.scan_ip_addresses:
        task_signatures.append(scan_ip_address.si(
            org_uuid=org_uuid,
            ip_address_uuid=ip_address_model.uuid,
            scan_network_services=False,
            order_uuid=order_uuid,
        ))
    if scan_config.scan_network_services:
        task_signatures.append(scan_network_service.si(
            org_uuid=org_uuid,
            network_service_uuid=network_service_model.uuid,
            check_liveness=False,
            liveness_cause="zmap scan",
            order_uuid=order_uuid,
        ))
    if len(task_signatures) > 0:
        canvas_sig = group(task_signatures)
        canvas_sig.apply_async()
    else:
        logger.warning("No tasks were created as a result of handle_live_zmap_service.")
